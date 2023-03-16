local config = require "config"

if config.isWAFOn and config.isProtectionMode then
    if ngx.status ~= 403 then
        if config.isSensitiveDataFilteringOn then
            ngx.header.content_length = nil
        end
    else
        ngx.header.server = "ZhongKui WAF"
    end
end