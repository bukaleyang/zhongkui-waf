-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local config = require "config"

if config.isWAFOn and config.isProtectionMode then
    if ngx.status ~= 403 then
        if config.isSensitiveDataFilteringOn or config.isBotTrapOn then
            ngx.header.content_length = nil
        end
    else
        ngx.header.server = "ZhongKui WAF"
    end
end