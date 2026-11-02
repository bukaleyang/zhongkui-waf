-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local config = require "config"

local get_site_config = config.get_site_config
local is_site_option_on = config.is_site_option_on

-- ACME HTTP-01 challenge responses must not be modified by header filters
local request_uri = ngx.var.uri
if request_uri and request_uri:sub(1, 28) == "/.well-known/acme-challenge/" then
    return
end

if is_site_option_on("waf") and get_site_config("waf").mode == "protection" then
    if ngx.status ~= 403 then
        if is_site_option_on("sensitiveDataFilter") or (is_site_option_on("bot") and get_site_config("bot").trap.state == "on") then
            ngx.header.content_length = nil
        end
    else
        ngx.header.server = "ZhongKui WAF"
    end
end