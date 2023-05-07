local config = require "config"
local time = require "time"

local upper = string.upper

local ATTACK_PREFIX = "attack_"
local ATTACK_TYPE_PREFIX = "attack_type_"

-- 按小时统计当天请求流量，存入缓存，key格式：2023-05-05 09
local function countRequestTraffic()
    local hour = time.getDateHour()
    local dict = ngx.shared.dict_req_count
    local count, err = dict:incr(hour, 1)
    if not count and err == "not found" then
        local expireTime = time.getExpireTime()
        dict:set(hour, 1, expireTime)
    end
end

--[[
    按小时统计当天攻击请求流量，存入缓存，key格式：attack_2023-05-05 09
    按天统计当天所有攻击类型流量，存入缓存，key格式：attack_type_2023-05-05_ARGS
]]
local function countAttackRequestTraffic(ruleTable)
    local ruleType = upper(ruleTable.ruleType)
    local dict = ngx.shared.dict_req_count
    local count, err = nil, nil

    if ruleType ~= 'WHITEIP' then
        local hour = time.getDateHour()
        local key = ATTACK_PREFIX .. hour
        count, err = dict:incr(key, 1)
        if not count and err == "not found" then
            local expireTime = time.getExpireTime()
            dict:set(key, 1, expireTime)
        end
    end

    local today = ngx.today() .. '_'
    local typeKey = ATTACK_TYPE_PREFIX .. today .. ruleType
    count, err = dict:incr(typeKey, 1)

    if not count and err == "not found" then
        local expireTime = time.getExpireTime()
        dict:set(typeKey, 1, expireTime)
    end
end

if config.isWAFOn and config.isDashboardOn then
    countRequestTraffic()

    local ruleTable = ngx.ctx.ruleTable
    if ruleTable then
        countAttackRequestTraffic(ruleTable)
    end
end
