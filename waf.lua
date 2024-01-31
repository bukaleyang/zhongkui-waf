-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local geoip = require "geoip"
local config = require "config"
local lib = require "lib"
local ipUtils = require "ip"
local request = require "request"

local generateId = request.generateId

local geoip_default = {isAllowed = true, country = '', province = '', city = ''}

local function init()
    local ip = ipUtils.getClientIP()
    ngx.ctx.ip = ip

    local ua = ngx.var.http_user_agent
    if ua == nil then
        ua = ""
    end
    ngx.ctx.ua = ua

    if config.isGeoIPOn then
        ngx.ctx.geoip = geoip.lookup(ip)
    else
        ngx.ctx.geoip = geoip_default
    end

    ngx.ctx.requestId = generateId()
end

if config.isWAFOn then

    init()

    if lib.isWhiteIp() then

    elseif lib.isBlackIp() then

    elseif lib.isUnsafeHttpMethod() then

    elseif lib.isBot() then

    elseif lib.isCC() then

    elseif lib.isWhiteURL() then

    elseif lib.isBlackURL() then

    elseif lib.isEvilArgs() then

    elseif lib.isEvilHeaders() then

    elseif lib.isEvilReqBody() then

    elseif lib.isEvilCookies() then

    elseif lib.isACL() then

    end

end
