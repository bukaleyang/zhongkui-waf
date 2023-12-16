local cjson = require "cjson"
local config = require "config"
local file = require "file"
local ipUtils = require "ip"
local aes = require "lib.aes"

local md5 = ngx.md5
local upper = string.upper
local sub = string.sub

local random = math.random

local _M = {}

local PASSWORD_PATH = config.ZHONGKUI_PATH .. '/admin/admin/data/user.json'
local SALT_LENGTH = 20
local AUTH_TOKEN_EXPIRE_TIME = 1800

-- 生成指定长度的随机盐
local function generateSalt(length)
    local saltChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local charLength = #saltChars
    local salt = ""

    for i = 1, length do
        local randomIndex = random(1, charLength)
        salt = salt .. sub(saltChars, randomIndex, randomIndex)
    end

    return salt
end

-- 对密码进行加密
local function encryptPassword(password, salt)
    return upper(md5(md5(password .. salt)))
end

-- 验证请求中的AuthToken
function _M.checkAuthToken()
    local authtoken = ngx.var.cookie_waf_authtoken

    if authtoken then
        local realIp =  ipUtils.getClientIP()
        local ua = ngx.var.http_user_agent or ''
        local salt = sub(md5(realIp .. ua .. config.secret), 1, 8)

        local tokenJson = aes.decrypt(config.secret, authtoken, salt)
        if tokenJson then
            local token = cjson.decode(tokenJson)
            local expTime = token.expTime
            local time = ngx.time()

            if time < expTime then
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
function _M.setAuthToken()
    local realIp =  ipUtils.getClientIP()
    local ua = ngx.var.http_user_agent or ''
    local salt = sub(md5(realIp .. ua .. config.secret), 1, 8)
    local time = ngx.time()

    local token = { ip = realIp, ua = ua, tokenTime = time, expTime = time + AUTH_TOKEN_EXPIRE_TIME }
    local authtoken = aes.encrypt(config.secret, cjson.encode(token), salt)

    local cookieExpire = ngx.cookie_time(time + AUTH_TOKEN_EXPIRE_TIME)
    ngx.header['Set-Cookie'] = { 'waf_authtoken=' .. authtoken .. '; path=/; Expires=' .. cookieExpire }
end

-- 清除浏览器cookie:authtoken
function _M.clearAuthToken()
    ngx.header['Set-Cookie'] = { 'waf_authtoken=; path=/; Expires=Thu, 01-Jan-1970 00:00:00 GMT' }
end

function _M.doRequest()
    local response = { code = 200, data = {}, msg = "" }
    local uri = ngx.var.uri

    if uri ~= '/user/login' then
        if _M.checkAuthToken() == false then
            response.code = 401
            response.msg = 'User not logged in'
            ngx.status = 401
            ngx.say(cjson.encode(response))
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
                local json = file.readFileToString(PASSWORD_PATH)
                if json then
                    local passwdTable = cjson.decode(json)
                    local uname = passwdTable.username
                    local upasswd = passwdTable.password
                    local salt = passwdTable.salt
                    local passwd = encryptPassword(password, salt)

                    if username ~= uname or upasswd ~= passwd then
                        response.code = 201
                        response.msg = '用户名或密码错误'
                        ngx.log(ngx.ERR, 'waf user login failed,wrong username or password')
                    else
                        _M.setAuthToken()
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
                local json = file.readFileToString(PASSWORD_PATH)
                if json then
                    local passwdTable = cjson.decode(json)
                    local upasswd = passwdTable.password
                    local salt = passwdTable.salt
                    local passwd = encryptPassword(oldPassword, salt)

                    if upasswd == passwd then
                        local newSalt = generateSalt(SALT_LENGTH)
                        local newPasswordStr = encryptPassword(newPassword, newSalt)
                        passwdTable.salt = newSalt
                        passwdTable.password = newPasswordStr
                        file.writeStringToFile(PASSWORD_PATH, cjson.encode(passwdTable))
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
        _M.clearAuthToken()
    end

    ngx.say(cjson.encode(response))
end

return _M
