local config = require "config"
local redisCli = require "redisCli"
local cc = require "cc"

local md5 = ngx.md5
local upper = string.upper

local _M = {}

local dict_hits = ngx.shared.dict_config_rules_hits
local RULES_HIT_PREFIX = "waf_rules_hits:"
local RULES_HIT_EXPTIME = 60

local function deny(status)
    if config.isProtectionMode then
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
        ngx.header.content_type = "text/html; charset=UTF-8"
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say(config.html)
        return ngx.exit(ngx.status)
    end
end

-- block ip
function _M.blockIp(ip, ruleTab)
    if upper(ruleTab.autoIpBlock) == "ON" and ip then
        local ok, err = nil, nil

        if config.isRedisOn then
            local key = "black_ip:" .. ip

            local red, err1 = redisCli.getRedisConn()
            if not red then
                return nil, err1
            end

            local exists = red:exists(key)
            if exists == 0 then
                ok, err = red:set(key, 1)
                if ok then
                    ngx.ctx.ipBlocked = true
                else
                    ngx.log(ngx.ERR, "failed to set redis key " .. key, err)
                end
            end

            if ruleTab.ipBlockTimeout > 0 then
                ok, err = red:expire(key, ruleTab.ipBlockTimeout)
                if not ok then
                    ngx.log(ngx.ERR, "failed to expire redis key " .. key, err)
                end
            end

            redisCli.closeRedisConn(red)
        else
            local blackip = ngx.shared.dict_blackip
            local exists = blackip:get(ip)
            if not exists then
                ok, err = blackip:set(ip, 1, ruleTab.ipBlockTimeout)
                if ok then
                    ngx.ctx.ipBlocked = true
                else
                    ngx.log(ngx.ERR, "failed to set key " .. ip, err)
                end
            elseif ruleTab.ipBlockTimeout > 0 then
                ok, err = blackip:expire(ip, ruleTab.ipBlockTimeout)
                if not ok then
                    ngx.log(ngx.ERR, "failed to expire key " .. ip, err)
                end
            end
        end

        return ok
    end
end

local function hit(ruleTable)
    if config.isRulesSortOn then
        local ruleMd5Str = md5(ruleTable.rule)
        local ruleType = ruleTable.ruleType
        local key = RULES_HIT_PREFIX .. ruleType .. '_' .. ruleMd5Str
        local key_total = RULES_HIT_PREFIX .. ruleType .. '_total_' .. ruleMd5Str
        local newHits = nil
        local newTotalHits = nil

        if config.isRedisOn then
            local count = redisCli.redisGet(key)
            if not count then
                redisCli.redisSet(key, 1, RULES_HIT_EXPTIME)
            else
                newHits, _ = redisCli.redisIncr(key)
            end
            newTotalHits, _ = redisCli.redisIncr(key_total)
        else
            newHits, _ = dict_hits:incr(key, 1, 0, RULES_HIT_EXPTIME)
            newTotalHits, _ = dict_hits:incr(key_total, 1, 0)
        end

        ruleTable.hits = newHits or 1
        ruleTable.totalHits = newTotalHits or 1
    end
end

function _M.doAction(ruleTable, data, ruleType, status)
    local action = upper(ruleTable.action)
    if ruleType == nil then
        ruleType = ruleTable.ruleType
    else
        ruleTable.ruleType = ruleType
    end

    hit(ruleTable)
    ngx.ctx.ruleTable = ruleTable
    ngx.ctx.action = action
    ngx.ctx.hitData = data
    ngx.ctx.isAttack = true

    if action == "ALLOW" then

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
