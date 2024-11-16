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

-- 查询日志列表数据
local function listLogs()
    local response = {code = 200, data = {}, msg = ""}

    local args, err = ngx.req.get_uri_args()
    if args then
        local page = tonumber(args['page'])
        local limit = tonumber(args['limit'])
        local offset = pager.get_begin(page, limit)

        local ip = args['ip']
        local block_reason = args['block_reason']

        local where = ' WHERE 1=1 '

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
                res, err = mysql.query(SQL_SELECT_IP_BLOCK_LOG .. where .. ' ORDER BY id DESC LIMIT ' .. offset .. ',' .. limit)
                if res then
                    response.data = res
                else
                    response.code = 500
                    response.msg = 'query database error'
                    ngx.log(ngx.ERR, err)
                end
            end

            response.code = 0
            response.count = total
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
