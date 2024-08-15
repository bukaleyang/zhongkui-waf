-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local geoip = require "geoip"
local config = require "config"
local lib = require "lib"
local ipUtils = require "ip"
local request = require "request"
local stringutf8 = require "stringutf8"

local defaultIfBlank = stringutf8.defaultIfBlank
local generateId = request.generateId
local is_site_option_on = config.is_site_option_on

local function init()
    local ctx = ngx.ctx

    local ip = ipUtils.getClientIP()
    ctx.ip = ip

    local ua = ngx.var.http_user_agent
    if ua == nil then
        ua = ""
    end

    ctx.ua = ua

    ctx.geoip = geoip.lookup(ip)

    ctx.requestId = generateId()

    ctx.server_name = defaultIfBlank(ngx.var.server_name, 'unknown')
end

if is_site_option_on("waf") then

    init()

    if lib.isWhiteIp() then

    elseif lib.isBlackIp() then

    elseif lib.isUnsafeHttpMethod() then

    elseif lib.isACL() then

    elseif lib.isBot() then

    elseif lib.isCC() then

    elseif lib.isWhiteURL() then

    elseif lib.isBlackURL() then

    elseif lib.isEvilArgs() then

    elseif lib.isEvilHeaders() then

    elseif lib.isEvilCookies() then

    elseif lib.isEvilReqBody() then

    end

end
