local config = require "config"
local redisCli = require "redisCli"
local loggerFactory = require "loggerFactory"
local cc = require "cc"

local md5 = ngx.md5
local toUpper = string.upper

local _M = {}

local logPath = config.get("logPath")
local rulePath = config.get("rulePath")

local dict_hits = ngx.shared.dict_config_rules_hits
local RULES_HIT_PREFIX = "waf_rules_hits:"
local RULES_HIT_EXPTIME = 60

local function writeLog(ruleType, data, rule, action)
    if config.isAttackLogOn then
        local realIp = ngx.ctx.ip
        local geoName = ngx.ctx.geoip.name
        local method = ngx.req.get_method()
        local url = ngx.var.request_uri
        local ua = ngx.ctx.ua
        local host = ngx.var.server_name
        local time = ngx.localtime()
        if ua == nil or ua == "" then
            ua = "-"
        end
        if action == nil or action == "" then
            action = "-"
        end
        local logStr = ruleType .. " " .. realIp .. " " .. geoName .. " [" .. time .. "] \"" .. method .. " " .. host .. url .. "\" \"" .. data .. "\"  \"" .. ua .. "\" \"" .. rule .. "\" " .. action .. "\n"

        local hostLogger = loggerFactory.getLogger(logPath, host, true)
        hostLogger:log(logStr)
    end
end

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
        if config.isRedirectOn then
            ngx.header.content_type = "text/html; charset=UTF-8"
            ngx.status = ngx.HTTP_FORBIDDEN
            ngx.say(config.html)
            return ngx.exit(ngx.status)
        end

        return deny()
    end
end

-- block ip
function _M.blockIp(ip, ruleTab)
    if toUpper(ruleTab.autoIpBlock) == "ON" and ip then

        local ok, err, exists = nil, nil, nil

        if config.isRedisOn then
            local key = "black_ip:" .. ip
            if ruleTab.ipBlockTimeout > 0 then
                exists = redisCli.redisGet(key)
                if not exists then
                    ok, err = redisCli.redisSet(key, 1, ruleTab.ipBlockTimeout)
                end
            else
                exists = redisCli.redisGet(key)
                if not exists then
                    ok, err = redisCli.redisSet(key, 1)
                end
            end
        else
            local blackip = ngx.shared.dict_blackip
            exists = blackip:get(ip)
            if not exists then
                ok, err = blackip:set(ip, 1, ruleTab.ipBlockTimeout)
            end
        end

        if ok then
            local hostLogger = loggerFactory.getLogger(logPath .. "ipBlock.log", 'ipBlock', false)
            hostLogger:log(ngx.localtime() .. " " .. ip .. "\n")

            if ruleTab.ipBlockTimeout == 0 then
                local ipBlackLogger = loggerFactory.getLogger(rulePath .. "ipBlackList", 'ipBlack', false)
                ipBlackLogger:log(ip .. "\n")
            end
        end

        return ok
    end
end

local function hit(ruleTable)
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

function _M.doAction(ruleTable, data, ruleType, status)
    local rule = ruleTable.rule
    local action = toUpper(ruleTable.action)
    if ruleType == nil then
        ruleType = ruleTable.ruleType
    else
        ruleTable.ruleType = ruleType
    end

    hit(ruleTable)
    ngx.ctx.ruleTable = ruleTable

    if action == "ALLOW" then
        writeLog(ruleType, data, rule, "ALLOW")
    elseif action == "DENY" then
        writeLog(ruleType, data, rule, "DENY")
        deny(status)
    elseif action == "REDIRECT" then
        writeLog(ruleType, data, rule, "REDIRECT")
        redirect()
    elseif action == "REDIRECT_302" then
        writeLog(ruleType, data, rule, "REDIRECT_302")
        cc.redirect302()
    elseif action == "REDIRECT_JS" then
        writeLog(ruleType, data, rule, "REDIRECT_JS")
        cc.redirectJS()
    else
        writeLog(ruleType, data, rule, "REDIRECT")
        redirect()
    end
end

return _M