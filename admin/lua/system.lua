-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local cjson = require "cjson"
local config = require "config"
local file = require "file_utils"
local ipmatcher = require "resty.ipmatcher"
local realip = require "lib.realip"
local user = require "user"
local request = require "request"

local get_post_args = request.get_post_args
local cjson_encode = cjson.encode
local cjson_decode = cjson.decode
local read_file_to_string = file.read_file_to_string
local write_string_to_file = file.write_string_to_file
local write_string_to_file_atomic = file.write_string_to_file_atomic

local type = type

local _M = {}

local SYSTEM_PATH = config.CONF_PATH .. '/system.json'

local function waf_conf_path()
    return config.ZHONGKUI_PATH .. '/admin/conf/waf.conf'
end

local function is_valid_cidr(cidr)
    local ok, matcher, err = pcall(ipmatcher.new, { cidr })
    if not ok then
        return false, tostring(matcher)
    end
    return matcher ~= nil, err
end

local function handle_realip_update(response)
    local args, err = get_post_args()
    if not args then
        response.code = 500
        response.msg = err or "参数读取失败"
        return
    end

    if type(args.realIp) ~= "string" then
        response.code = 400
        response.msg = "缺少真实 IP 配置"
        return
    end

    local decoded_ok, decoded = pcall(cjson_decode, args.realIp)
    if not decoded_ok or type(decoded) ~= "table" then
        response.code = 400
        response.msg = "真实 IP 配置格式不正确"
        return
    end

    local cfg = realip.normalize(decoded)
    local valid, valid_err = realip.validate(cfg, is_valid_cidr)
    if not valid then
        response.code = 400
        response.msg = valid_err
        return
    end

    local old_system = read_file_to_string(SYSTEM_PATH)
    if not old_system then
        response.code = 500
        response.msg = "读取系统配置失败"
        return
    end

    local system_ok, system = pcall(cjson_decode, old_system)
    if not system_ok or type(system) ~= "table" then
        response.code = 500
        response.msg = "系统配置格式不正确"
        return
    end

    local waf_path = waf_conf_path()
    local old_waf_conf = read_file_to_string(waf_path)
    if not old_waf_conf then
        response.code = 500
        response.msg = "读取 nginx WAF 配置失败"
        return
    end

    system.realIp = cfg
    local new_system = cjson_encode(system)
    local new_waf_conf = realip.replace_block(old_waf_conf, realip.build_block(cfg))

    local wrote, write_err = write_string_to_file_atomic(waf_path, new_waf_conf)
    if not wrote then
        response.code = 500
        response.msg = "写入 nginx 配置失败: " .. tostring(write_err)
        return
    end

    -- 先做 nginx -t，避免把错误配置写进 system.json 后才发现
    local passed, detail = config.test_nginx_config_detail()
    if not passed then
        write_string_to_file_atomic(waf_path, old_waf_conf)
        response.code = 500
        response.msg = "nginx 配置校验失败: " .. tostring(detail)
        return
    end

    local saved, save_err = write_string_to_file_atomic(SYSTEM_PATH, new_system)
    if not saved then
        write_string_to_file_atomic(waf_path, old_waf_conf)
        response.code = 500
        response.msg = "保存系统配置失败: " .. tostring(save_err)
        return
    end

    -- 已经通过 nginx -t，跳过重复校验
    local reloaded, reload_err = config.reload_nginx(true)
    if not reloaded then
        write_string_to_file_atomic(waf_path, old_waf_conf)
        write_string_to_file_atomic(SYSTEM_PATH, old_system)
        response.code = 500
        response.msg = "nginx 重载失败: " .. tostring(reload_err)
        return
    end

    config.load_config_file()
    response.data = cfg
end

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
    elseif uri == "/system/realip/update" then
        handle_realip_update(response)
    end

    ngx.say(cjson_encode(response))

    -- 如果没有错误且需要重载配置文件则重载配置文件
    if (response.code == 200 or response.code == 0) and reload == true then
        config.reload_config_file()
    end
end

_M.do_request()

return _M
