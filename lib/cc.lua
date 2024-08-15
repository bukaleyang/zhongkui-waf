-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local config = require "config"
local redisCli = require "redisCli"
local nkeys = require "table.nkeys"

local concat = table.concat
local type = type

local len = string.len
local sub = string.sub
local md5 = ngx.md5
local pairs = pairs
local tonumber = tonumber
local upper = string.upper

local get_site_config = config.get_site_config
local is_system_option_on = config.is_system_option_on
local get_system_config = config.get_system_config

local SECRET = get_system_config("secret")

local _M = {}

-- 浏览器验证，302重定向
function _M.redirect302()
    local reqUri = ngx.var.request_uri
    local args = ngx.req.get_uri_args()
    local time = ngx.time()

    local reqSign = ngx.var.arg_redirect302_sign
    local reqTime = tonumber(ngx.var.arg_redirect302_time)

    if reqSign and reqTime and type(reqTime) == "number" and ((reqTime + get_site_config("cc").actionTimeout) >= time) then
        local pass = _M.signVerify(args, "redirect302_sign", SECRET)
        if pass then
            -- 设置访问令牌
            _M.setAccessToken()
        end
    else
        args["redirect302_time"] = time
        local sign = _M.getSign(args, 'redirect302_sign', SECRET)
        local newUri = ''
        if nkeys(args) > 1 then
            newUri = reqUri .. '&redirect302_sign=' .. sign .. '&redirect302_time=' .. time
        else
            newUri = reqUri .. '?redirect302_sign=' .. sign .. '&redirect302_time=' .. time
        end

        _M.clearAccessToken()
        ngx.redirect(newUri, 302)
    end

    return ngx.exit(302)
end

-- 浏览器验证，js重定向
function _M.redirectJS()
    local reqUri = ngx.var.request_uri
    local args = ngx.req.get_uri_args()
    local time = ngx.time()

    local reqSign = ngx.var.arg_redirectjs_sign
    local reqTime = tonumber(ngx.var.arg_redirectjs_time)

    if reqSign and reqTime and type(reqTime) == "number" and ((reqTime + get_site_config("cc").actionTimeout) >= time) then
        local pass = _M.signVerify(args, "redirectjs_sign", SECRET)
        if pass then
            -- 设置访问令牌
            _M.setAccessToken()
        end
    else
        args["redirectjs_time"] = time
        local sign = _M.getSign(args, 'redirectjs_sign', SECRET)
        local newUri = ''
        if nkeys(args) > 1 then
            newUri = reqUri .. '&redirectjs_sign=' .. sign .. '&redirectjs_time=' .. time
        else
            newUri = reqUri .. '?redirectjs_sign=' .. sign .. '&redirectjs_time=' .. time
        end

        _M.clearAccessToken()
        ngx.header.content_type = "text/html"
        ngx.print("<script>window.location.href='" .. newUri .. "';</script>")
    end

    return ngx.exit(ngx.HTTP_OK)
end

-- 验证请求中的AccessToken，验证通过则返回true,否则返回false
function _M.checkAccessToken()
    local accesstoken = ngx.var.cookie_waf_accesstoken

    if not accesstoken then
        return false
    end

    local ctx = ngx.ctx
    local realIp = ctx.ip
    local ua = ctx.ua
    local key = md5(realIp .. ua .. SECRET)

    local token = nil
    if is_system_option_on("redis") then
        local prefix = "cc_req_accesstoken:"
        token = redisCli.redisGet(prefix .. key)
    else
        local limit = ngx.shared.dict_accesstoken
        token = limit:get(key)
    end

    if token and token == accesstoken then
        return true
    end

    return false
end

-- 设置浏览器cookie:accesstoken
function _M.setAccessToken()
    local realIp = ngx.ctx.ip
    local ua = ngx.ctx.ua
    local key = md5(realIp .. ua .. SECRET)
    local time = ngx.time()

    local accesstoken = upper(md5(key .. time))
    local cookieExpire = ngx.cookie_time(time + get_site_config("cc").accessTokenTimeout)
    ngx.header['Set-Cookie'] = { 'waf_accesstoken=' .. accesstoken .. '; path=/; Expires=' .. cookieExpire }

    if is_system_option_on("redis") then
        local prefix = "cc_req_accesstoken:"
        redisCli.redisSet(prefix .. key, accesstoken, get_site_config("cc").accessTokenTimeout)
    else
        local limit = ngx.shared.dict_accesstoken
        limit:set(key, accesstoken, get_site_config("cc").accessTokenTimeout)
    end
end

-- 清除浏览器cookie:accesstoken
function _M.clearAccessToken()
    ngx.header['Set-Cookie'] = { 'waf_accesstoken=; path=/; Expires=Thu, 01-Jan-1970 00:00:00 GMT' }
end

-- 获取请求签名
function _M.getSign(args, signKey, secret)
    local str = ''

    if args then
        table.sort(args)

        for key, val in pairs(args) do
            if key ~= signKey then
                if type(val) == "table" then
                    str = str .. '&' .. key .. '=' .. concat(val, ", ")
                else
                    str = str .. '&' .. key .. '=' .. val
                end
            end
        end

        local length = len(str)
        if length > 1 then
            str = sub(str, 2)
        end
    end

    str = str .. '&secret=' .. secret

    local sign = upper(md5(str))

    return sign
end

-- 验证请求签名
function _M.signVerify(args, signKey, secret)
    if args then
        local reqSign = args[signKey]
        if not reqSign then
            return false
        end

        local sign = _M.getSign(args, signKey, secret)

        if reqSign == sign then
            return true
        end
    end

    return false
end

return _M
