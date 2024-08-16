-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local cjson = require "cjson"
local config = require "config"
local redis_cli = require "redis_cli"
local isarray = require "table.isarray"
local sql = require "sql"
local utils = require "utils"
local constants = require "constants"

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
            hits = redis_cli.get(prefix .. key)
            totalHits = redis_cli.get(prefix .. key_total)
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

local sort_timer_handler = function(premature)
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
                    if isarray(rules) then
                        rules = sort(server_name .. module['moduleName'], rules)
                    end
                end

                local json_new = cjson_encode(security_modules)
                dict_config:set(server_name, json_new)
            end
        end
    end
end

local get_rules_timer_handler = function(premature)
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
    local worker_id = ngx.worker.id()

    if is_system_option_on('rulesSort') then
        local delay = get_system_config('rulesSort').period

        if worker_id == 0 then
            utils.start_timer_every(delay, sort_timer_handler)
        end

        utils.start_timer_every(delay, get_rules_timer_handler)
    end

    if is_system_option_on("mysql") then
        if worker_id == 0 then
            utils.start_timer(0, sql.check_table)
            utils.start_timer_every(2, sql.write_sql_queue_to_mysql, constants.KEY_ATTACK_LOG)
            utils.start_timer_every(2, sql.write_sql_queue_to_mysql, constants.KEY_IP_BLOCK_LOG)
            utils.start_timer_every(2, sql.update_waf_status)
            utils.start_timer_every(2, sql.update_traffic_stats)
        end
    end

end
