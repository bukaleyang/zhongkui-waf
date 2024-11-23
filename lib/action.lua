-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local config = require "config"
local redis_cli = require "redis_cli"
local captcha = require "captcha"
local constants = require "constants"
local request = require "request"

local md5 = ngx.md5
local ngxsub = ngx.re.sub
local upper = string.upper
local ostime = os.time
local osdate = os.date

local get_site_config = config.get_site_config
local is_system_option_on = config.is_system_option_on
local get_system_config = config.get_system_config

local _M = {}

local dict_hits = ngx.shared.dict_config_rules_hits
local RULES_HIT_PREFIX = "waf_rules_hits:"
local RULES_HIT_EXPTIME = 60
local REDIRECT_HTML = get_system_config().html
local REGEX_OPTION = "jo"

local function deny(status)
    if get_site_config("waf").mode == "protection" then
        ngx.ctx.is_blocked = true

        return ngx.exit(status or ngx.HTTP_FORBIDDEN)
    else
        ngx.ctx.action = "ALLOW"
    end
end

local function redirect()
    if get_site_config("waf").mode == "protection" then
        ngx.ctx.is_blocked = true
        ngx.header.content_type = "text/html; charset=UTF-8"
        ngx.status = ngx.HTTP_FORBIDDEN
        local ctx = ngx.ctx
        local html = REDIRECT_HTML

        html = ngxsub(html, "\\$remote_addr", ctx.ip, REGEX_OPTION)
        html = ngxsub(html, "\\$request_id", ctx.request_id, REGEX_OPTION)
        html = ngxsub(html, "\\$blocked_time", osdate("%Y-%m-%d %H:%M:%S", ostime()), REGEX_OPTION)
        html = ngxsub(html, "\\$user_agent", ctx.ua, REGEX_OPTION)

        ngx.say(html)
        return ngx.exit(ngx.status)
    end
end

-- block ip
function _M.block_ip(ip, rule_table)
    if upper(rule_table.autoIpBlock) == "ON" and ip then
        local ok, err = nil, nil

        if is_system_option_on("redis") then
            local key = constants.KEY_BLACKIP_PREFIX .. ip

            ok, err = redis_cli.set(key, 1, rule_table.ipBlockExpireInSeconds)
            if ok then
                ngx.ctx.ip_blocked = true
            else
                ngx.log(ngx.ERR, "failed to block ip " .. ip, err)
            end
        else
            local blackip = ngx.shared.dict_blackip
            ok, err = blackip:set(ip, 1, rule_table.ipBlockExpireInSeconds)
            if ok then
                ngx.ctx.ip_blocked = true
            else
                ngx.log(ngx.ERR, "failed to block ip " .. ip, err)
            end
        end

        return ok
    end
end

function _M.unblock_ip(ip)
    local ok, err = nil, nil

    if is_system_option_on("redis") then
        local key = constants.KEY_BLACKIP_PREFIX .. ip
        ok, err = redis_cli.del(key)
    else
        local blackip = ngx.shared.dict_blackip

        ok, err = blackip:delete(ip)
        if not ok then
            ngx.log(ngx.ERR, "failed to delete key " .. ip, err)
        end
    end

    return ok
end

local function hit(module_name, rule_table)
    if is_system_option_on('rulesSort') then
        local ruleMd5Str = md5(rule_table.rule)
        local server_name = ngx.ctx.server_name
        local attackType = server_name .. module_name
        local key = RULES_HIT_PREFIX .. attackType .. '_' .. ruleMd5Str
        local key_total = RULES_HIT_PREFIX .. attackType .. '_total_' .. ruleMd5Str
        local newHits = nil
        local newTotalHits = nil

        if is_system_option_on("redis") then
            local count = redis_cli.get(key)
            if not count then
                redis_cli.set(key, 1, RULES_HIT_EXPTIME)
            else
                newHits = redis_cli.incr(key)
            end
            newTotalHits = redis_cli.incr(key_total)
        else
            newHits = dict_hits:incr(key, 1, 0, RULES_HIT_EXPTIME)
            newTotalHits = dict_hits:incr(key_total, 1, 0)
        end

        rule_table.hits = newHits or 1
        rule_table.totalHits = newTotalHits or 1
    end
end

function _M.do_action(module_name, rule_table, data, attackType, status)
    local action = upper(rule_table.action)
    if attackType == nil then
        attackType = rule_table.attackType
    else
        rule_table.attackType = attackType
    end

    hit(module_name, rule_table)
    ngx.ctx.module_name = module_name
    ngx.ctx.rule_table = rule_table
    ngx.ctx.action = action
    ngx.ctx.hit_data = data
    ngx.ctx.is_attack = true

    request.get_request_body()

    if action == "ALLOW" then
        return ngx.exit(ngx.OK)
    elseif action == "DENY" then
        deny(status)
    elseif action == "REDIRECT" then
        redirect()
    elseif action == "CAPTCHA" then
        ngx.ctx.is_attack = false
        captcha.trigger_captcha()
    else
        redirect()
    end
end

return _M
