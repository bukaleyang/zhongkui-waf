local sensitive = require "sensitive"
local config = require "config"

local content = ngx.arg[1]

if config.isWAFOn and config.isProtectionMode then
    if ngx.status ~= 403 then
        if config.isSensitiveDataFilteringOn then
            if content then
                content = sensitive.sensitive_data_filtering(content)
            end
        end
    end
end

ngx.arg[1] = content