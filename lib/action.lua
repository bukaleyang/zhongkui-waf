-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local config = require "config"
local redisCli = require "redisCli"
local cc = require "cc"
local constants = require "constants"

local md5 = ngx.md5
local ngxsub = ngx.re.sub
local upper = string.upper
local ostime = os.time
local osdate = os.date

local _M = {}

local dict_hits = ngx.shared.dict_config_rules_hits
local RULES_HIT_PREFIX = "waf_rules_hits:"
local RULES_HIT_EXPTIME = 60
local REDIRECT_HTML = config.html
local REGEX_OPTION = "jo"

local function deny(status)
    if config.isProtectionMode then
        ngx.ctx.blocked = true
        local statusCode = ngx.HTTP_FORBIDDEN
        if status then
            statusCode = status
        end

        ngx.status = statusCode
        return ngx.exit(ngx.status)
    end
end

local function redirect()
    if config.isProtectionMode then
        ngx.ctx.blocked = true
        ngx.header.content_type = "text/html; charset=UTF-8"
        ngx.status = ngx.HTTP_FORBIDDEN
        local ctx = ngx.ctx
        local html = REDIRECT_HTML

        html = ngxsub(html, "\\$remote_addr", ctx.ip, REGEX_OPTION)
        html = ngxsub(html, "\\$request_id", ctx.requestId, REGEX_OPTION)
        html = ngxsub(html, "\\$blocked_time", osdate("%Y-%m-%d %H:%M:%S", ostime()), REGEX_OPTION)
        html = ngxsub(html, "\\$user_agent", ctx.ua, REGEX_OPTION)

        ngx.say(html)
        return ngx.exit(ngx.status)
    end
end

-- block ip
function _M.blockIp(ip, ruleTab)
    if upper(ruleTab.autoIpBlock) == "ON" and ip then
        local ok, err = nil, nil

        if config.isRedisOn then
            local key = constants.KEY_BLACKIP_PREFIX .. ip

            ok, err = redisCli.redisSet(key, 1, ruleTab.ipBlockTimeout)
            if ok then
                ngx.ctx.ipBlocked = true
            else
                ngx.log(ngx.ERR, "failed to block ip " .. ip, err)
            end
        else
            local blackip = ngx.shared.dict_blackip
            ok, err = blackip:set(ip, 1, ruleTab.ipBlockTimeout)
            if ok then
                ngx.ctx.ipBlocked = true
            else
                ngx.log(ngx.ERR, "failed to block ip " .. ip, err)
            end
        end

        return ok
    end
end

function _M.unblockIp(ip)
    local ok, err = nil, nil

    if config.isRedisOn then
        local key = constants.KEY_BLACKIP_PREFIX .. ip
        ok, err = redisCli.redisDel(key)
    else
        local blackip = ngx.shared.dict_blackip

        ok, err = blackip:delete(ip)
        if not ok then
            ngx.log(ngx.ERR, "failed to delete key " .. ip, err)
        end
    end

    return ok
end

local function hit(ruleTable)
    if config.isRulesSortOn then
        local ruleMd5Str = md5(ruleTable.rule)
        local attackType = ruleTable.attackType
        local key = RULES_HIT_PREFIX .. attackType .. '_' .. ruleMd5Str
        local key_total = RULES_HIT_PREFIX .. attackType .. '_total_' .. ruleMd5Str
        local newHits = nil
        local newTotalHits = nil

        if config.isRedisOn then
            local count = redisCli.redisGet(key)
            if not count then
                redisCli.redisSet(key, 1, RULES_HIT_EXPTIME)
            else
                newHits = redisCli.redisIncr(key)
            end
            newTotalHits = redisCli.redisIncr(key_total)
        else
            newHits = dict_hits:incr(key, 1, 0, RULES_HIT_EXPTIME)
            newTotalHits = dict_hits:incr(key_total, 1, 0)
        end

        ruleTable.hits = newHits or 1
        ruleTable.totalHits = newTotalHits or 1
    end
end

function _M.doAction(moduleName, ruleTable, data, attackType, status)
    local action = upper(ruleTable.action)
    if attackType == nil then
        attackType = ruleTable.attackType
    else
        ruleTable.attackType = attackType
    end

    hit(ruleTable)
    ngx.ctx.moduleName = moduleName
    ngx.ctx.ruleTable = ruleTable
    ngx.ctx.action = action
    ngx.ctx.hitData = data
    ngx.ctx.isAttack = true

    if action == "ALLOW" then
        ngx.status = ngx.HTTP_OK
        return ngx.exit(ngx.status)
    elseif action == "DENY" then
        deny(status)
    elseif action == "REDIRECT" then
        redirect()
    elseif action == "REDIRECT_302" then
        cc.redirect302()
    elseif action == "REDIRECT_JS" then
        cc.redirectJS()
    else
        redirect()
    end
end

return _M
