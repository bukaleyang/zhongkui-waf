-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local cjson = require "cjson"
local config = require "config"
local redisCli = require "redisCli"
local isArray = require "table.isarray"
local sql = require "sql"
local utils = require "utils"
local constants = require "constants"

local redisGet = redisCli.redisGet
local md5 = ngx.md5
local pairs = pairs
local tonumber = tonumber

local dict_config = ngx.shared.dict_config
local dict_hits = ngx.shared.dict_config_rules_hits

local prefix = "waf_rules_hits:"

local function sort(ruleType, t)
    for _, rt in pairs(t) do
        local ruleMd5Str = md5(rt.rule)
        local key = ruleType .. '_' .. ruleMd5Str
        local key_total = ruleType .. '_total_' .. ruleMd5Str

        local hits = nil
        local totalHits = nil

        if config.isRedisOn then
            hits = redisGet(prefix .. key)
            totalHits = redisGet(prefix .. key_total)
        else
            hits = dict_hits:get(key)
            totalHits = dict_hits:get(key_total)
        end

        rt.hits = tonumber(hits) or 0
        rt.totalHits = tonumber(totalHits) or 0
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

    local jsonStr = dict_config:get("securityModules")
    local securityModules = cjson.decode(jsonStr)

    for k, _ in pairs(securityModules) do
        local rulesTable = securityModules[k].rules

        if isArray(rulesTable) then
            rulesTable = sort(k, rulesTable)
        end
    end

    local newJsonStr = cjson.encode(securityModules)
    dict_config:set("securityModules", newJsonStr)
end

local getRulesTimerHandler = function(premature)
    if premature then
        return
    end

    local jsonStr = dict_config:get("securityModules")
    local securityModules = cjson.decode(jsonStr)
    config.securityModules = securityModules
end

if config.isWAFOn then
    local workerId = ngx.worker.id()

    if config.isRulesSortOn then
        local delay = config.rulesSortPeriod

        if workerId == 0 then
            utils.startTimerEvery(delay, sortTimerHandler)
        end

        utils.startTimerEvery(delay, getRulesTimerHandler)
    end

    if config.isMysqlOn then
        if workerId == 0 then
            utils.startTimer(0, sql.checkTable)
            utils.startTimerEvery(2, sql.writeSqlQueueToMysql, constants.KEY_ATTACK_LOG)
            utils.startTimerEvery(2, sql.writeSqlQueueToMysql, constants.KEY_IP_BLOCK_LOG)
            utils.startTimerEvery(2, sql.updateWafStatus)
            utils.startTimerEvery(2, sql.updateTrafficStats)
        end
    end

end
