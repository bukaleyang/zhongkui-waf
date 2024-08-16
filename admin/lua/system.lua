-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local cjson = require "cjson"
local config = require "config"
local file = require "file_utils"
local user = require "user"
local request = require "request"

local get_post_args = request.get_post_args
local cjson_encode = cjson.encode
local cjson_decode = cjson.decode
local read_file_to_string = file.read_file_to_string
local write_string_to_file = file.write_string_to_file

local type = type

local _M = {}

local SYSTEM_PATH = config.CONF_PATH .. '/system.json'

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

    if uri == "/system/get" then
        -- 查询配置信息
        local system = config.get_system_config()
        if system then
            -- 清空用户名和密码，避免返回给前端
            local redis = system.redis
            local mysql = system.mysql
            redis.user = nil
            redis.password = nil
            mysql.user = nil
            mysql.password = nil
            response.data = cjson_encode(system)
        end
    elseif uri == "/system/update" then
        local args, err = get_post_args()
        if args then
            local json = read_file_to_string(SYSTEM_PATH)
            local system = cjson_decode(json)

            for key, val in pairs(args) do
                local option = system[key]

                if key == 'secret' then
                    option = val
                else
                    local t = cjson_decode(val)
                    if type(t) == 'table' and type(option) == 'table' then
                        for k, v in pairs(t) do
                            option[k] = v
                        end
                    else
                        option = val
                    end
                end

                system[key] = option
            end

            write_string_to_file(SYSTEM_PATH, cjson_encode(system))
            reload = true
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
