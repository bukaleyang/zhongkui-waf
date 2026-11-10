-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local sensitive = require "sensitive_data_filter"
local config = require "config"

local ngxfind = ngx.re.find
local gsub = string.gsub
local format = string.format
local sub = string.sub

local get_site_config = config.get_site_config
local is_site_option_on = config.is_site_option_on
local get_system_config = config.get_system_config

local CONTENT_TYPE_REGEX = "^(?:text/html|text/plain|text/xml|application/json|application/xml|application/xhtml\\+xml)"
local HTML_CONTENT_TYPE_REGEX = "^(?:text/html|application/xhtml\\+xml)"
local TRAP_HTML = '<a href="%s" class="honeyLink">come-here</a><style>.honeyLink{display:none;}</style></body>'
-- 仅限制攻击日志中保存的响应体，WAF 检测仍使用完整内容
local MAX_BODY_LEN = get_system_config('logLimit').maxResponseBodyLen

-- ACME HTTP-01 challenge responses must not be modified by body filters
local request_uri = ngx.var.uri
if request_uri and request_uri:sub(1, 28) == "/.well-known/acme-challenge/" then
    return
end

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
    if is_attack and content then
        local response_body = ngx.ctx.response_body or ""
        -- 只追加到上限，避免大响应在 ctx 中反复拼接并占用内存
        if #response_body < MAX_BODY_LEN then
            ngx.ctx.response_body = sub(response_body .. content, 1, MAX_BODY_LEN)
        end
    end

end

ngx.arg[1] = content
