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

local _M = {}

-- 浏览器验证，302重定向
function _M.redirect302()
    local reqUri = ngx.var.request_uri
    local args = ngx.req.get_uri_args()
    local time = ngx.time()

    local reqSign = ngx.var.arg_redirect302_sign
    local reqTime = tonumber(ngx.var.arg_redirect302_time)

    if reqSign and reqTime and type(reqTime) == "number" and ((reqTime + config.ccActionTimeout) >= time) then
        local pass = _M.signVerify(args, "redirect302_sign", config.secret)
        if pass then
            -- 设置访问令牌
            _M.setAccessToken()
            return true
        else
            return false
        end
    else
        args["redirect302_time"] = time
        local sign = _M.getSign(args, 'redirect302_sign', config.secret)
        local newUri = ''
        if nkeys(args) > 1 then
            newUri = reqUri .. '&redirect302_sign=' .. sign .. '&redirect302_time=' .. time
        else
            newUri = reqUri .. '?redirect302_sign=' .. sign .. '&redirect302_time=' .. time
        end

        _M.clearAccessToken()
        ngx.redirect(newUri, 302)

        return
    end
end

-- 浏览器验证，js重定向
function _M.redirectJS()
    local reqUri = ngx.var.request_uri
    local args = ngx.req.get_uri_args()
    local time = ngx.time()

    local reqSign = ngx.var.arg_redirectjs_sign
    local reqTime = tonumber(ngx.var.arg_redirectjs_time)

    if reqSign and reqTime and type(reqTime) == "number" and ((reqTime + config.ccActionTimeout) >= time) then
        local pass = _M.signVerify(args, "redirectjs_sign", config.secret)
        if pass then
            -- 设置访问令牌
            _M.setAccessToken()
            return true
        else
            return false
        end
    else
        args["redirectjs_time"] = time
        local sign = _M.getSign(args, 'redirectjs_sign', config.secret)
        local newUri = ''
        if nkeys(args) > 1 then
            newUri = reqUri .. '&redirectjs_sign=' .. sign .. '&redirectjs_time=' .. time
        else
            newUri = reqUri .. '?redirectjs_sign=' .. sign .. '&redirectjs_time=' .. time
        end

        _M.clearAccessToken()
        ngx.header.content_type = "text/html"
        ngx.print("<script>window.location.href='" .. newUri .. "';</script>")
        ngx.exit(200)

        return
    end
end

-- 验证请求中的AccessToken，验证通过则返回true,否则返回false
function _M.checkAccessToken()
    local accesstoken = ngx.var.cookie_waf_accesstoken

    if not accesstoken then
        return false
    end

    local realIp = ngx.ctx.ip
    local ua = ngx.ctx.ua
    local key = md5(realIp .. ua .. config.secret)

    local token = nil
    if config.isRedisOn then
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
    local key = md5(realIp .. ua .. config.secret)

    local time = ngx.time()

    local accesstoken = upper(md5(key .. time))
    local cookieExpire = ngx.cookie_time(time + config.ccAccessTokenTimeout)
    ngx.header['Set-Cookie'] = { 'waf_accesstoken=' .. accesstoken .. '; path=/; Expires=' .. cookieExpire }

    if config.isRedisOn then
        local prefix = "cc_req_accesstoken:"
        redisCli.redisSet(prefix .. key, accesstoken, config.ccAccessTokenTimeout)
    else
        local limit = ngx.shared.dict_accesstoken
        limit:set(key, accesstoken, config.ccAccessTokenTimeout)
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
