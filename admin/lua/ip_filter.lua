-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local cjson = require "cjson"
local config = require "config"
local file = require "file_utils"
local user = require "user"
local nkeys = require "table.nkeys"
local stringutf8 = require "stringutf8"
local request = require "lib.request"

local tonumber = tonumber
local trim = stringutf8.trim
local read_file_to_string = file.read_file_to_string
local read_file_to_table = file.read_file_to_table
local write_string_to_file = file.write_string_to_file

local get_site_config = config.get_site_config
local get_site_config_file = config.get_site_config_file
local update_site_config_file = config.update_site_config_file

local cjson_decode = cjson.decode
local cjson_encode = cjson.encode

local get_request_body = request.get_request_body

local _M = {}

local IP_WHITELIST_PATH = config.CONF_PATH .. '/global_rules/ipWhiteList'
local IP_BLACKLIST_PATH = config.CONF_PATH .. '/global_rules/ipBlackList'


function _M.do_request()
    local response = {code = 200, data = {}, msg = ""}
    local uri = ngx.var.uri
    local reload = false

    if user.check_auth_token() == false then
        response.code = 401
        response.msg = 'User not logged in'
        ngx.status = 401
        ngx.say(cjson_encode(response))
        ngx.exit(401)
        return
    end

    if uri == "/ip/filter/config/get" then
        local args, err = ngx.req.get_uri_args()
        if args then
            local site_id = tostring(args['siteId'])
            local _, content = get_site_config_file(site_id)

            local data = {}
            local site_config = cjson_decode(content)
            if site_config then
                data.whiteIP = site_config.whiteIP
                data.blackIP = site_config.blackIP
                data.disallowCountrys = site_config.geoip.disallowCountrys
            end

            response.data = cjson_encode(data)
        else
            response.code = 500
            response.msg = err
        end
    elseif uri == "/ip/filter/config/state/update" then
        -- 修改IP黑白名单启用状态
         ngx.req.read_body()
         local args, err = ngx.req.get_post_args()

         if args then
            local site_id = tostring(args['siteId'])
            local state = args.state
            local _, content = get_site_config_file(site_id)

            if state and content then
                local config_table = cjson_decode(content)

                if args.whiteIP then
                    config_table.whiteIP.state = state
                end

                if args.blackIP then
                    config_table.blackIP.state = state
                end

                local new_config_json = cjson_encode(config_table)
                update_site_config_file(site_id, new_config_json)
                reload = true
            else
                response.code = 500
                response.msg = 'param error'
            end
         else
             response.code = 500
             response.msg = err
         end
    elseif uri == "/ip/filter/rule/list" then
        -- ip黑白名单列表
        local data = {}
        local content = ''

        local ip_white_list = read_file_to_table(IP_WHITELIST_PATH)
        if ip_white_list then
            local len = nkeys(ip_white_list)
            if len > 1 then
                content = ip_white_list[1] .. '...'
            elseif len > 0 then
                content = ip_white_list[1]
            end
        end

        data[1] = {id = 1, state = get_site_config("whiteIP").state, content = content}

        content = ''
        local ip_black_list = read_file_to_table(IP_BLACKLIST_PATH)
        if ip_black_list then
            local len = nkeys(ip_black_list)
            if len > 1 then
                content = ip_black_list[1] .. '...'
            elseif len > 0 then
                content = ip_black_list[1]
            end
        end

        data[2] = {id = 2, state = get_site_config("blackIP").state, content = content}

        response.data = data
        response.count = 2
        response.code = 0
    elseif uri == "/ip/filter/rule/get" then
        -- ip黑白名单内容
        local args, err = ngx.req.get_uri_args()
        if args then
            local id = tonumber(args['id'])
            if id then
                local content = ''
                if id == 1 then
                    content = read_file_to_string(IP_WHITELIST_PATH) or ''
                elseif id == 2 then
                    content = read_file_to_string(IP_BLACKLIST_PATH) or ''
                end
                response.data = {id = id, content = content}
            end
        else
            response.code = 500
            response.msg = err
        end
    elseif uri == "/ip/filter/rule/update" then
        -- 修改ip黑白名单内容
        local id = nil
        local content = nil
        local args = nil

        local body_raw = get_request_body()

        if body_raw and body_raw ~= "" then
            args = ngx.decode_args(body_raw, 0)
        end

        if args then
            id = tonumber(args['id'])
            content = args['content']

            if id and content then
                if id == 1 then
                    write_string_to_file(IP_WHITELIST_PATH, trim(content))
                elseif id == 2 then
                    write_string_to_file(IP_BLACKLIST_PATH, trim(content))
                end
                reload = true
            end
        end
    elseif uri == "/ip/filter/rule/geo/update" then
        -- 修改地域级IP黑名单配置
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()
        if args then
            local site_id = tostring(args['siteId'])
            local countries = tostring(args['countries'])

            if site_id and countries then
                local _, content = get_site_config_file(site_id)
                if content then
                    local t = cjson_decode(content)
                    local geoip = t.geoip
                    geoip.disallowCountrys = cjson_decode(countries)

                    local json = cjson_encode(t)
                    update_site_config_file(site_id, json)
                    reload = true
                end
            else
                response.code = 500
                response.msg = 'param error'
            end
        else
            response.code = 500
            response.msg = err
        end
    end

    ngx.say(cjson_encode(response))

    -- 如果没有错误且需要重载配置文件则重载配置文件
    if (response.code == 200 or response.code == 0) and reload == true then
        config.reload_config_file()
    end
end

_M.do_request()

return _M
