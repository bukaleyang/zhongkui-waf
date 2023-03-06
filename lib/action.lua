local config = require "config"
local redisCli = require "redisCli"
local loggerFactory = require "loggerFactory"

local toUpper = string.upper
local md5 = ngx.md5

local _M = {}

local dict_hits = ngx.shared.dict_config_rules_hits
local logPath = config.get("logPath")
local rulePath = config.get("rulePath")

local prefix = "waf_rules_hits:"
local exptime = 60
        
local function writeLog(ruleType, data, rule, action)
    if config.isAttackLogOn then
        local realIp = ngx.ctx.ip
        local geoName = ngx.ctx.geoip.name
        local method = ngx.req.get_method()
        local url = ngx.var.request_uri
        local ua = ngx.var.http_user_agent
        local host = ngx.var.server_name
        local time = ngx.localtime()
        if ua == nil or ua == "" then
            ua = "-"
        end
        if action == nil or action == "" then
            action = "-"
        end
        line = ruleType .. " " .. realIp .. " " .. geoName .. " [" .. time .. "] \"" .. method .. " " .. host .. url .. "\" \"" .. data .. "\"  \"" .. ua .. "\" \"" .. rule .. "\" " .. action .. "\n"

        local hostLogger = loggerFactory.getLogger(logPath, host, true)
        hostLogger:log(line)
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
function _M.blockIp(ip)
    if config.isAutoIpBlockOn and ip then
        
        local ok, err, exists = nil, nil, nil
        
        if config.isRedisOn then
            if config.ipBlockTimeout > 0 then
                local key = "black_ip:" .. ip
                exists = redisCli.redisGet(key)
                if not exists then
                    ok, err = redisCli.redisSet(key, 1, config.ipBlockTimeout)
                end
            else
                exists = redisCli.redisBFExists(ip)
                if not exists then
                    ok, err = redisCli.redisBFAdd(ip)
                end
            end
        else
            local blackip = ngx.shared.dict_blackip
            exists = blackip:get(ip)
            if not exists then
                ok, err = blackip:set(ip, 1, config.ipBlockTimeout)
            end
        end

        if ok then
            local hostLogger = loggerFactory.getLogger(logPath .. "ipBlock.log", 'ipBlock', false)
            hostLogger:log(ngx.localtime() .. " " .. ip .. "\n")
            
            if config.ipBlockTimeout == 0 then
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
    local key = ruleType .. '_' .. ruleMd5Str
    local key_total = ruleType .. '_total_' .. ruleMd5Str
    local newHits = 1
    local newTotalHits = 1
    
    if config.isRedisOn then
        local count = redisCli.redisGet(prefix .. key)
        if not count then
            redisCli.redisSet(prefix .. key, 1, exptime)
        else
            newHits, _ = redisCli.redisIncr(prefix .. key)
        end
        newTotalHits, _ = redisCli.redisIncr(prefix .. key_total)
    else
        newHits, _ = dict_hits:incr(key, 1, 0, exptime)
        newTotalHits, _ = dict_hits:incr(key_total, 1, 0)
    end

    ruleTable.hits = newHits
    ruleTable.totalHits = newTotalHits
end

function _M.doAction(ruleTable, data, ruleType, status)
    local rule = ruleTable.rule
    local action = toUpper(ruleTable.action)
    if ruleType == nil then
        ruleType = ruleTable.ruleType
    end
    
    hit(ruleTable)
    
    if action == "ALLOW" then
        writeLog(ruleType, data, rule, "ALLOW")
    elseif action == "DENY" then
        writeLog(ruleType, data, rule, "DENY")
        deny(status)
    elseif action == "REDIRECT" then
        writeLog(ruleType, data, rule, "REDIRECT")
        redirect()
    else
        writeLog(ruleType, data, rule, "REDIRECT")
        redirect()
    end
end

return _M