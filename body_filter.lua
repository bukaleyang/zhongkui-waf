local sensitive = require "sensitive"
local config = require "config"

local ngxfind = ngx.re.find
local gsub = string.gsub

local CONTENT_TYPE_REGEX = "^(?:text/html|text/plain|text/xml|application/json|application/xml|application/xhtml\\+xml)"
local HTML_CONTENT_TYPE_REGEX = "^(?:text/html|application/xhtml\\+xml)"

local TRAP_URI = config.botTrapUri
local TRAP_HTML = '<a href="' .. TRAP_URI .. '" class="honeyLink">come-here</a><style>.honeyLink{display:none;}</style></body>'

local content = ngx.arg[1]

if config.isWAFOn and config.isProtectionMode then
    if ngx.status ~= 403 then
        local contentType = ngx.header.content_type or ''
        if config.isSensitiveDataFilteringOn then
            if contentType then
                local from = ngxfind(contentType, CONTENT_TYPE_REGEX, "isjo")
                if from then
                    if content then
                        content = sensitive.sensitive_data_filtering(content)
                    end
                end
            end

        end

        if config.isBotTrapOn then
            if contentType then
                local from = ngxfind(contentType, HTML_CONTENT_TYPE_REGEX, "isjo")
                if from then
                    if content then
                        content = gsub(content, '</body>', TRAP_HTML)
                    end
                end
            end
        end
    end
end

ngx.arg[1] = content
