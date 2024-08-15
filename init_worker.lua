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

local cjson_decode = cjson.decode
local cjson_encode = cjson.encode

local dict_config = ngx.shared.dict_config
local dict_hits = ngx.shared.dict_config_rules_hits

local is_global_option_on = config.is_global_option_on
local is_system_option_on = config.is_system_option_on
local get_system_config = config.get_system_config

local prefix = "waf_rules_hits:"

local function sort(key_str, t)
    for _, rt in pairs(t) do
        local rule_md5 = md5(rt.rule)
        local key = key_str .. '_' .. rule_md5
        local key_total = key_str .. '_total_' .. rule_md5

        local hits = nil
        local totalHits = nil

        if is_system_option_on("redis") then
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

    local config_table = config.get_config_table()
    if config_table then
        for server_name, _ in pairs(config_table) do
            local json = dict_config:get(server_name)
            if json then
                local security_modules = cjson_decode(json)
                for _, module in pairs(security_modules) do
                    local rules = module.rules
                    if isArray(rules) then
                        rules = sort(server_name .. module['moduleName'], rules)
                    end
                end

                local json_new = cjson_encode(security_modules)
                dict_config:set(server_name, json_new)
            end
        end
    end
end

local getRulesTimerHandler = function(premature)
    if premature then
        return
    end

    local config_table = config.get_config_table()
    if config_table then
        for key, conf in pairs(config_table) do
            local json = dict_config:get(key)
            if json then
                local security_modules = cjson_decode(json)
                conf.security_modules = security_modules
            end
        end
    end
end

if is_global_option_on("waf") then
    local workerId = ngx.worker.id()

    if is_system_option_on('rulesSort') then
        local delay = get_system_config().rulesSort.period

        if workerId == 0 then
            utils.startTimerEvery(delay, sortTimerHandler)
        end

        utils.startTimerEvery(delay, getRulesTimerHandler)
    end

    if is_system_option_on("mysql") then
        if workerId == 0 then
            utils.startTimer(0, sql.checkTable)
            utils.startTimerEvery(2, sql.writeSqlQueueToMysql, constants.KEY_ATTACK_LOG)
            utils.startTimerEvery(2, sql.writeSqlQueueToMysql, constants.KEY_IP_BLOCK_LOG)
            utils.startTimerEvery(2, sql.updateWafStatus)
            utils.startTimerEvery(2, sql.updateTrafficStats)
        end
    end

end
