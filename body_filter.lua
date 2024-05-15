-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local sensitive = require "sensitive"
local config = require "config"
local stringutf8 = require "stringutf8"

local ngxfind = ngx.re.find
local gsub = string.gsub
local defaultIfBlank = stringutf8.defaultIfBlank

local CONTENT_TYPE_REGEX = "^(?:text/html|text/plain|text/xml|application/json|application/xml|application/xhtml\\+xml)"
local HTML_CONTENT_TYPE_REGEX = "^(?:text/html|application/xhtml\\+xml)"

local TRAP_URI = config.botTrapUri
local TRAP_HTML = '<a href="' .. TRAP_URI .. '" class="honeyLink">come-here</a><style>.honeyLink{display:none;}</style></body>'

local content = ngx.arg[1]

if config.isWAFOn then
    if config.isProtectionMode then
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

            if config.isBotOn and config.isBotTrapOn then
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

    local isAttack = ngx.ctx.isAttack
    if isAttack then
        local response_body = ngx.ctx.response_body
        if content then
            ngx.ctx.response_body = defaultIfBlank(response_body, "") .. content
        end
    end

end

ngx.arg[1] = content
