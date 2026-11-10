-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

local cjson = require "cjson"
local user = require "user"
local pager = require "lib.pager"
local mysql = require "mysql_cli"
local action = require "action"

local tonumber = tonumber
local format = string.format
local quote_sql_str = ngx.quote_sql_str
local cjson_encode = cjson.encode

local _M = {}

local SQL_COUNT_IP_BLOCK_LOG = 'SELECT COUNT(*) AS total FROM ip_block_log '

local SQL_SELECT_IP_BLOCK_LOG = [[
    SELECT id, request_id, ip, ip_country_code, ip_country_cn, ip_country_en, ip_province_code, ip_province_cn, ip_province_en, ip_city_code, ip_city_cn, ip_city_en,
    ip_longitude, ip_latitude, block_reason, start_time, block_duration, end_time, unblock_time, action, block_times FROM ip_block_log
]]

local SQL_IP_BLOCK_LOG_UNBLOCK = [[
    UPDATE ip_block_log SET unblock_time=NOW() WHERE id=%u;
]]

-- 时间格式固定 YYYY-MM-DD HH:mm:ss；无参数时兜底查当天，避免对 ip_block_log 做全表 COUNT
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

        local ip = args['ip']
        local block_reason = args['block_reason']

        local start_time, end_time, time_err = get_time_range(args)
        if time_err then
            response.code = 500
            response.msg = time_err
            return response
        end

        -- 回传实际生效范围，前端据此回填输入框
        response.startTime = start_time
        response.endTime = end_time

        local where = ' WHERE start_time >= ' .. quote_sql_str(start_time)
            .. ' AND start_time <= ' .. quote_sql_str(end_time) .. ' '

        if ip and #ip > 0 then
            where = where .. ' AND ip=' .. quote_sql_str(ip) .. ' '
        end

        if block_reason and #block_reason > 0 then
            where = where .. ' AND block_reason=' .. quote_sql_str(block_reason) .. ' '
        end

        local res, err = mysql.query(SQL_COUNT_IP_BLOCK_LOG .. where)

        if res and res[1] then
            local total = tonumber(res[1].total)
            if total > 0 then
                -- 按时间倒序可以走 start_time 索引并直接取前 N 条；
                -- 用 ORDER BY id 在宽时间范围下会扫描大量行并 filesort。
                res, err = mysql.query(SQL_SELECT_IP_BLOCK_LOG .. where .. ' ORDER BY start_time DESC, id DESC LIMIT ' .. offset .. ',' .. limit)
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

-- 根据id解封ip
local function unblock()
    local response = {code = 200, data = {}, msg = ""}

    local args, err = ngx.req.get_post_args()
    if args and args['id'] then
        local id = tonumber(args['id'])

        local res, err = mysql.query(format(SQL_SELECT_IP_BLOCK_LOG .. ' WHERE id=%u;', id))
        if res then
            local data = res[1]
            local ip = data.ip

            local ok = action.unblock_ip(ip)
            if ok then
                res, err = mysql.query(format(SQL_IP_BLOCK_LOG_UNBLOCK, id))
                if res then
                    response.data = res[1]
                else
                    response.code = 500
                    response.msg = 'query database error'
                    ngx.log(ngx.ERR, err)
                end
            end
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

    if uri == "/ipblocking/list" then
        -- 查询事件数据列表
        response = listLogs()
    elseif uri == "/ipblocking/unblock" then
        -- ip解封
        response = unblock()
    end

    ngx.say(cjson_encode(response))
end

_M.do_request()

return _M
