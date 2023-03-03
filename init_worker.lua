local cjson = require "cjson"
local config = require "config"
local redisCli = require "redisCli"
local isArray = require "table.isarray"

local redisGet = redisCli.redisGet
local every = ngx.timer.every
local md5 = ngx.md5
local pairs = pairs
local tonumber = tonumber

local dict_config = ngx.shared.dict_config
local dict_hits = ngx.shared.dict_config_rules_hits

local prefix = "waf_rules_hits:"
local delay = config.rulesSortPeriod

local function sort(ruleType, t)
    for _, rt in pairs(t) do
        local ruleMd5Str = md5(rt.rule)
        local key = ruleType .. '_' .. ruleMd5Str
        local key_total = ruleType .. '_total_' .. ruleMd5Str
        
        local hits = 0
        local totalHits = 0
        
        if config.isRedisOn then
            hits = redisGet(prefix .. key)
            totalHits = redisGet(prefix .. key_total)
        else
            hits = dict_hits:get(key)
            totalHits = dict_hits:get(key_total)
        end
        
        hits = (hits ~= nil and hits or 0)
        totalHits = (totalHits ~= nil and totalHits or 0)
        rt.hits = tonumber(hits)
        rt.totalHits = tonumber(totalHits)
    end
    
    table.sort(t, function(a, b)
        if a.hits > b.hits then
            return true
        elseif a.hits == b.hits then
            if a.totalHits > b.totalHits then
                return true
            end
        end
        return false
    end)
    return t
end

local sortTimerHandler = function(premature)
    if premature then
        return
    end

    local jsonStr = dict_config:get("rules")
    local rulesConfig = cjson.decode(jsonStr)

    for k, _ in pairs(rulesConfig) do
        local rulesTable = rulesConfig[k]

        if isArray(rulesTable) then
            rulesTable = sort(k, rulesTable)
        end
    end
    
    local newJsonStr = cjson.encode(rulesConfig)
    dict_config:set("rules", newJsonStr)
end

local getRulesTimerHandler = function(premature)
    if premature then
        return
    end

    local jsonStr = dict_config:get("rules")
    local rulesConfig = cjson.decode(jsonStr)
    config.rules = rulesConfig
end

if config.isRulesSortOn then
    local workerId = ngx.worker.id()
    if workerId == 0 then
        local ok, err = every(delay, sortTimerHandler)
        if not ok then
            ngx.log(ngx.ERR, "failed to create the timer: ", err)
            return
        end
    end

    local ok, err = every(delay, getRulesTimerHandler)
    if not ok then
        ngx.log(ngx.ERR, "failed to create the timer: ", err)
        return
    end
end
