-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local cjson = require "cjson"
local config = require "config"
local file = require "file_utils"
local ip_utils = require "ip_utils"
local aes = require "lib.aes"

local md5 = ngx.md5
local upper = string.upper
local sub = string.sub

local random = math.random
local get_system_config = config.get_system_config
local read_file_to_string = file.read_file_to_string
local write_string_to_file = file.write_string_to_file
local get_client_ip = ip_utils.get_client_ip

local cjson_decode = cjson.decode
local cjson_encode = cjson.encode

local secret = get_system_config("secret")

local _M = {}

local PASSWORD_PATH = config.ZHONGKUI_PATH .. '/admin/admin/data/user.json'
local SALT_LENGTH = 20
local AUTH_TOKEN_EXPIRE_TIME = 1800

-- 生成指定长度的随机盐
local function generate_salt(length)
    local salt_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local char_length = #salt_chars
    local salt = ""

    for i = 1, length do
        local random_index = random(1, char_length)
        salt = salt .. sub(salt_chars, random_index, random_index)
    end

    return salt
end

-- 对密码进行加密
local function encrypt_password(password, salt)
    return upper(md5(md5(password .. salt)))
end

-- 验证请求中的AuthToken
function _M.check_auth_token()
    local authtoken = ngx.var.cookie_waf_authtoken

    if authtoken then
        local ip =  get_client_ip()
        local ua = ngx.var.http_user_agent or ''
        local salt = sub(md5(ip .. ua .. secret), 1, 8)

        local token_json = aes.decrypt(secret, authtoken, salt)
        if token_json then
            local token = cjson_decode(token_json)
            local exp_time = token.exp_time
            local time = ngx.time()

            if time < exp_time then
                return true
            else
                ngx.log(ngx.INFO, 'waf user login timeout')
                return false
            end
        else
            ngx.log(ngx.INFO, 'waf user auth token decrypt failed')
            return false
        end
    else
        ngx.log(ngx.INFO, 'waf user auth token not exists')
    end

    return false
end

-- 设置浏览器cookie:authtoken
function _M.set_auth_token()
    local ip =  get_client_ip()
    local ua = ngx.var.http_user_agent or ''
    local salt = sub(md5(ip .. ua .. secret), 1, 8)
    local time = ngx.time()

    local token = { ip = ip, ua = ua, token_time = time, exp_time = time + AUTH_TOKEN_EXPIRE_TIME }
    local authtoken = aes.encrypt(secret, cjson_encode(token), salt)

    local access_token = ngx.cookie_time(time + AUTH_TOKEN_EXPIRE_TIME)
    ngx.header['Set-Cookie'] = { 'waf_authtoken=' .. authtoken .. '; path=/; Expires=' .. access_token }
end

-- 清除浏览器cookie:authtoken
function _M.clear_auth_token()
    ngx.header['Set-Cookie'] = { 'waf_authtoken=; path=/; Expires=Thu, 01-Jan-1970 00:00:00 GMT' }
end

function _M.do_request()
    local response = { code = 200, data = {}, msg = "" }
    local uri = ngx.var.uri

    if uri ~= '/user/login' then
        if _M.check_auth_token() == false then
            response.code = 401
            response.msg = 'User not logged in'
            ngx.status = 401
            ngx.say(cjson_encode(response))
            ngx.exit(401)
            return
        end
    end

    if uri == "/user/login" then
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()

        if args then
            local username = args['username'] or ''
            local password = args['password'] or ''

            if username == '' then
                response.code = 201
                response.msg = '用户名或密码错误'
                ngx.log(ngx.ERR, 'waf user login failed,empty username')
            elseif password == '' then
                response.code = 201
                response.msg = '用户名或密码错误'
                ngx.log(ngx.ERR, 'waf user login failed,empty password')
            else
                local json = read_file_to_string(PASSWORD_PATH)
                if json then
                    local passwd_table = cjson_decode(json)
                    local uname = passwd_table.username
                    local upasswd = passwd_table.password
                    local salt = passwd_table.salt
                    local passwd = encrypt_password(password, salt)

                    if username ~= uname or upasswd ~= passwd then
                        response.code = 201
                        response.msg = '用户名或密码错误'
                        ngx.log(ngx.ERR, 'waf user login failed,wrong username or password')
                    else
                        _M.set_auth_token()
                        ngx.log(ngx.INFO, 'waf user login')
                    end
                end
            end
        else
            response.code = 500
            response.msg = err
        end
    elseif uri == "/user/password/update" then
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()

        if args then
            local oldPassword = args['oldPassword'] or ''
            local newPassword = args['newPassword'] or ''

            if oldPassword == '' then
                response.code = 201
                response.msg = '旧密码不能为空'
                ngx.log(ngx.ERR, 'waf user password update failed,empty old password')
            elseif newPassword == '' then
                response.code = 201
                response.msg = '新密码不能为空'
                ngx.log(ngx.ERR, 'waf user password update failed,empty new password')
            else
                local json = read_file_to_string(PASSWORD_PATH)
                if json then
                    local passwd_table = cjson_decode(json)
                    local upasswd = passwd_table.password
                    local salt = passwd_table.salt
                    local passwd = encrypt_password(oldPassword, salt)

                    if upasswd == passwd then
                        local salt_new = generate_salt(SALT_LENGTH)
                        local newPasswordStr = encrypt_password(newPassword, salt_new)
                        passwd_table.salt = salt_new
                        passwd_table.password = newPasswordStr
                        write_string_to_file(PASSWORD_PATH, cjson_encode(passwd_table))
                    else
                        response.code = 201
                        response.msg = '旧密码错误'
                    end
                end
            end
        else
            response.code = 500
            response.msg = err
        end
    elseif uri == "/user/logout" then
        _M.clear_auth_token()
    end

    ngx.say(cjson_encode(response))
end

return _M
