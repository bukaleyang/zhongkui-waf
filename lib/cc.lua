-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local config = require "config"
local redis_cli = require "redis_cli"
local nkeys = require "table.nkeys"

local concat = table.concat
local sort = table.sort
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
function _M.redirect_302()
    local request_uri = ngx.var.request_uri
    local args = ngx.req.get_uri_args()
    local time = ngx.time()

    local req_sign = ngx.var.arg_redirect302_sign
    local req_time = tonumber(ngx.var.arg_redirect302_time)

    if req_sign and req_time and type(req_time) == "number" and ((req_time + get_site_config("cc").actionTimeout) >= time) then
        local pass = _M.sign_verify(args, "redirect302_sign", SECRET)
        if pass then
            -- 设置访问令牌
            _M.set_access_token()
        end
    else
        args["redirect302_time"] = time
        local sign = _M.get_sign(args, 'redirect302_sign', SECRET)
        local uri_new = ''
        if nkeys(args) > 1 then
            uri_new = request_uri .. '&redirect302_sign=' .. sign .. '&redirect302_time=' .. time
        else
            uri_new = request_uri .. '?redirect302_sign=' .. sign .. '&redirect302_time=' .. time
        end

        _M.clear_access_token()
        ngx.redirect(uri_new, 302)
    end

    return ngx.exit(302)
end

-- 浏览器验证，js重定向
function _M.redirect_js()
    local request_uri = ngx.var.request_uri
    local args = ngx.req.get_uri_args()
    local time = ngx.time()

    local req_sign = ngx.var.arg_redirectjs_sign
    local req_time = tonumber(ngx.var.arg_redirectjs_time)

    if req_sign and req_time and type(req_time) == "number" and ((req_time + get_site_config("cc").actionTimeout) >= time) then
        local pass = _M.sign_verify(args, "redirectjs_sign", SECRET)
        if pass then
            -- 设置访问令牌
            _M.set_access_token()
        end
    else
        args["redirectjs_time"] = time
        local sign = _M.get_sign(args, 'redirectjs_sign', SECRET)
        local uri_new = ''
        if nkeys(args) > 1 then
            uri_new = request_uri .. '&redirectjs_sign=' .. sign .. '&redirectjs_time=' .. time
        else
            uri_new = request_uri .. '?redirectjs_sign=' .. sign .. '&redirectjs_time=' .. time
        end

        _M.clear_access_token()
        ngx.header.content_type = "text/html"
        ngx.print("<script>window.location.href='" .. uri_new .. "';</script>")
    end

    return ngx.exit(ngx.HTTP_OK)
end

-- 验证请求中的AccessToken，验证通过则返回true,否则返回false
function _M.check_access_token()
    local access_token = ngx.var.cookie_waf_accesstoken

    if not access_token then
        return false
    end

    local ctx = ngx.ctx
    local ip = ctx.ip
    local ua = ctx.ua
    local key = md5(ip .. ua .. SECRET)

    local token = nil
    if is_system_option_on("redis") then
        local prefix = "cc_req_accesstoken:"
        token = redis_cli.get(prefix .. key)
    else
        local limit = ngx.shared.dict_accesstoken
        token = limit:get(key)
    end

    if token and token == access_token then
        return true
    end

    return false
end

-- 设置浏览器cookie:access_token
function _M.set_access_token()
    local ip = ngx.ctx.ip
    local ua = ngx.ctx.ua
    local key = md5(ip .. ua .. SECRET)
    local time = ngx.time()

    local access_token = upper(md5(key .. time))
    local cookie_expire = ngx.cookie_time(time + get_site_config("cc").accessTokenTimeout)
    ngx.header['Set-Cookie'] = { 'waf_accesstoken=' .. access_token .. '; path=/; Expires=' .. cookie_expire }

    if is_system_option_on("redis") then
        local prefix = "cc_req_accesstoken:"
        redis_cli.set(prefix .. key, access_token, get_site_config("cc").accessTokenTimeout)
    else
        local limit = ngx.shared.dict_accesstoken
        limit:set(key, access_token, get_site_config("cc").accessTokenTimeout)
    end
end

-- 清除浏览器cookie:access_token
function _M.clear_access_token()
    ngx.header['Set-Cookie'] = { 'waf_accesstoken=; path=/; Expires=Thu, 01-Jan-1970 00:00:00 GMT' }
end

-- 获取请求签名
function _M.get_sign(args, sign_key, secret)
    local str = ''

    if args then
        sort(args)

        for key, val in pairs(args) do
            if key ~= sign_key then
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
function _M.sign_verify(args, sign_key, secret)
    if args then
        local req_sign = args[sign_key]
        if not req_sign then
            return false
        end

        local sign = _M.get_sign(args, sign_key, secret)

        if req_sign == sign then
            return true
        end
    end

    return false
end

return _M
