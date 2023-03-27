local sensitive = require "sensitive"
local config = require "config"

local ngxfind = ngx.re.find
local CONTENT_TYPE_REGEX = "^(?:text/html|text/plain|text/xml|application/json|application/xml|application/xhtml\\+xml)"

local content = ngx.arg[1]

if config.isWAFOn and config.isProtectionMode then
    if ngx.status ~= 403 then
        if config.isSensitiveDataFilteringOn then
            local contentType = ngx.header.content_type
            if contentType then
                local from = ngxfind(contentType, CONTENT_TYPE_REGEX, "isjo")
                if from then
                    if content then
                        content = sensitive.sensitive_data_filtering(content)
                    end
                end
            end

        end
    end
end

ngx.arg[1] = content