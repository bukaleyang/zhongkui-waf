-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local sensitive = require "sensitive_data_filter"
local config = require "config"
local stringutf8 = require "stringutf8"

local ngxfind = ngx.re.find
local gsub = string.gsub
local format = string.format
local default_if_blank = stringutf8.default_if_blank

local get_site_config = config.get_site_config
local is_site_option_on = config.is_site_option_on

local CONTENT_TYPE_REGEX = "^(?:text/html|text/plain|text/xml|application/json|application/xml|application/xhtml\\+xml)"
local HTML_CONTENT_TYPE_REGEX = "^(?:text/html|application/xhtml\\+xml)"
local TRAP_HTML = '<a href="%s" class="honeyLink">come-here</a><style>.honeyLink{display:none;}</style></body>'

local content = ngx.arg[1]

if is_site_option_on("waf") then
    if get_site_config("waf").mode == "protection" then
        if ngx.status ~= 403 then
            local content_type = ngx.header.content_type or ''
            if is_site_option_on("sensitiveDataFilter") then
                if content_type then
                    local from = ngxfind(content_type, CONTENT_TYPE_REGEX, "isjo")
                    if from then
                        if content then
                            content = sensitive.data_filter(content)
                        end
                    end
                end
            end

            if is_site_option_on("bot") then
                local trap = get_site_config("bot").trap
                local trap_uri = trap.uri or ''
                if trap.state == "on" then
                    if content_type then
                        local from = ngxfind(content_type, HTML_CONTENT_TYPE_REGEX, "isjo")
                        if from then
                            if content then
                                content = gsub(content, '</body>', format(TRAP_HTML, trap_uri))
                            end
                        end
                    end
                end
            end
        end
    end

    local is_attack = ngx.ctx.is_attack
    if is_attack then
        local response_body = ngx.ctx.response_body
        if content then
            ngx.ctx.response_body = default_if_blank(response_body, "") .. content
        end
    end

end

ngx.arg[1] = content
