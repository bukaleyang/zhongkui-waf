-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

local cjson = require "cjson"
local user = require "user"
local pager = require "lib.pager"
local mysql = require "mysql_cli"

local tonumber = tonumber
local quote_sql_str = ngx.quote_sql_str
local cjson_encode = cjson.encode

local _M = {}

local SQL_COUNT_ATTACK_LOG = 'SELECT COUNT(*) AS total FROM attack_log '

local SQL_SELECT_ATTACK_LOG = [[
    SELECT id, request_id, ip, ip_country_code, ip_country_cn, ip_country_en, ip_province_code, ip_province_cn, ip_province_en, ip_city_code, ip_city_cn, ip_city_en,
    ip_longitude, ip_latitude, http_method, server_name, user_agent, referer, request_protocol, request_uri,
    http_status, request_time, attack_type, severity_level, security_module, hit_rule, action FROM attack_log
]]

local SQL_SELECT_ATTACK_LOG_DETAIL = [[
    SELECT id, request_id, ip, ip_country_code, ip_country_cn, ip_country_en, ip_province_code, ip_province_cn, ip_province_en, ip_city_code, ip_city_cn, ip_city_en,
    ip_longitude, ip_latitude, http_method, server_name, user_agent, referer, request_protocol, request_uri,
    request_body, http_status, response_body, request_time, attack_type, severity_level, security_module, hit_rule, action FROM attack_log
]]

-- 时间格式固定 YYYY-MM-DD HH:mm:ss；无参数时兜底查当天，避免对 attack_log 做全表 COUNT
local TIME_PATTERN = '^%d%d%d%d%-%d%d%-%d%d %d%d:%d%d:%d%d$'
local MAX_PAGE_SIZE = 100
local MAX_SPAN_DAYS = 90 -- 与 admin/js/time-range.js 的 MAX_SPAN_DAYS 保持一致

local function date_only_timestamp(time_str)
    local y, mo, d = time_str:match('^(%d%d%d%d)%-(%d%d)%-(%d%d) ')
    return os.time({
        year = tonumber(y), month = tonumber(mo), day = tonumber(d),
        hour = 0, min = 0, sec = 0, isdst = false
    })
end

-- 都填 = [开始, 结束]；只填开始 = [开始, 现在]；只填结束报错；都不填 = 今天
-- 开始晚于结束、跨度超过 MAX_SPAN_DAYS 均报错
local function get_time_range(args)
    local start_time = args['startTime']
    local end_time = args['endTime']

    -- 非法格式按未填写处理，避免任意字符串进入 SQL
    if not start_time or not start_time:match(TIME_PATTERN) then
        start_time = nil
    end

    if not end_time or not end_time:match(TIME_PATTERN) then
        end_time = nil
    end

    local now = ngx.localtime()

    if not start_time and not end_time then
        return ngx.today() .. ' 00:00:00', now
    end

    if not start_time then
        return nil, nil, '请填写开始时间，结束时间不能单独使用'
    end

    if not end_time then
        end_time = now
    end

    if start_time > end_time then
        return nil, nil, '开始时间不能晚于结束时间'
    end

    -- 跨度按自然日计（含头含尾），与前端 dayCount 口径一致
    local span_days = math.floor((date_only_timestamp(end_time) - date_only_timestamp(start_time)) / 86400) + 1
    if span_days > MAX_SPAN_DAYS then
        return nil, nil, '查询范围最多 ' .. MAX_SPAN_DAYS .. ' 个自然日（当前 ' .. span_days .. ' 天），请缩小范围'
    end

    return start_time, end_time
end

-- 查询日志列表数据
local function listLogs()
    local response = {code = 200, data = {}, msg = ""}

    local args, err = ngx.req.get_uri_args()
    if args then
        local page = tonumber(args['page'])
        local limit = tonumber(args['limit'])
        if not limit or limit < 1 or limit > MAX_PAGE_SIZE then
            limit = 10
        end
        local offset = pager.get_begin(page, limit)

        local serverName = args['serverName']
        local ip = args['ip']
        local action = args['action']
        local attackType = args['attackType']

        local start_time, end_time, time_err = get_time_range(args)
        if time_err then
            response.code = 500
            response.msg = time_err
            return response
        end

        -- 回传实际生效范围，前端据此回填输入框
        response.startTime = start_time
        response.endTime = end_time

        local where = ' WHERE request_time >= ' .. quote_sql_str(start_time)
            .. ' AND request_time <= ' .. quote_sql_str(end_time) .. ' '

        if serverName and #serverName > 0 then
            -- 原来 LIKE '%域名%' 无法走索引；改为精确匹配，配合 request_time 索引使用。
            where = where .. ' AND server_name=' .. quote_sql_str(serverName) .. ' '
        end

        if ip and #ip > 0 then
            where = where .. ' AND ip=' .. quote_sql_str(ip) .. ' '
        end

        if attackType and #attackType > 0 then
            where = where .. ' AND attack_type=' .. quote_sql_str(attackType) .. ' '
        end

        if action and #action > 0 then
            where = where .. ' AND action=' .. quote_sql_str(action) .. ' '
        end

        local res, err = mysql.query(SQL_COUNT_ATTACK_LOG .. where)

        if res and res[1] then
            local total = tonumber(res[1].total)
            if total > 0 then
                -- 按时间倒序可以走 request_time 索引并直接取前 N 条；
                -- 用 ORDER BY id 在宽时间范围下会扫描大量行并 filesort。
                res, err = mysql.query(SQL_SELECT_ATTACK_LOG .. where .. ' ORDER BY request_time DESC, id DESC LIMIT ' .. offset .. ',' .. limit)
                if res then
                    response.data = res
                else
                    response.code = 500
                    response.msg = 'query database error'
                    ngx.log(ngx.ERR, err)
                end
            end

            if response.code ~= 500 then
                response.code = 0
                response.count = total
            end
        else
            response.code = 500
            response.msg = 'query database error'
            ngx.log(ngx.ERR, err)
        end
    else
        response.code = 500
        response.msg = err
    end

    if response.code ~= 0 then
        ngx.log(ngx.ERR, response.msg)
    end

    return response
end

-- 根据id查询日志详情
local function getLog()
    local response = {code = 200, data = {}, msg = ""}

    local args, err = ngx.req.get_uri_args()
    if args and args['id'] then
        local id = tonumber(args['id'])
        local where = ' WHERE id=' .. id

        local res, err = mysql.query(SQL_SELECT_ATTACK_LOG_DETAIL .. where)
        if res then
            response.data = res[1]
        else
            response.code = 500
            response.msg = 'query database error'
            ngx.log(ngx.ERR, err)
        end
    else
        response.code = 500
        response.msg = err
        ngx.log(ngx.ERR, err)
    end

    return response
end

function _M.do_request()
    local response = {code = 200, data = {}, msg = ""}
    local uri = ngx.var.uri

    if user.check_auth_token() == false then
        response.code = 401
        response.msg = 'User not logged in'
        ngx.status = 401
        ngx.say(cjson_encode(response))
        ngx.exit(401)
        return
    end

    if uri == "/events/list" then
        -- 查询事件数据列表
        response = listLogs()
    elseif uri == "/events/get" then
        -- 查询事件详情
        response = getLog()
    end

    ngx.say(cjson_encode(response))
end

_M.do_request()

return _M
