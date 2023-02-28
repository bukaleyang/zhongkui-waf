local config = require("config")
local redisCli = require("redisCli")
local loggerFactory = require("loggerFactory")
local toUpper = string.upper

local _M = {}

local logPath = config.get("logPath")
local rulePath = config.get("rulePath")

local function writeLog(logType, data, rule, action)
    if isAttackLogOn then
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
        line = logType .. " " .. realIp .. " " .. geoName .. " [" .. time .. "] \"" .. method .. " " .. host .. url .. "\" \"" .. data .. "\"  \"" .. ua .. "\" \"" .. rule .. "\" " .. action .. "\n"

        local hostLogger = loggerFactory.getLogger(logPath, host, true)
        hostLogger:log(line)
    end
end

local function deny(status)
    if isProtectionMode then
        local statusCode = ngx.HTTP_FORBIDDEN
        if status then
            statusCode = status
        end
        
        ngx.status = statusCode
        return ngx.exit(ngx.status)
    end
end

local function redirect()
    if isProtectionMode then
        if isRedirectOn then
            ngx.header.content_type = "text/html; charset=UTF-8"
            ngx.status = ngx.HTTP_FORBIDDEN
            ngx.say(config.get("html"))
            return ngx.exit(ngx.status)
        end
        
        return deny()
    end
end

-- block ip
function _M.blockIp(ip)
    if isAutoIpBlockOn and ip then
        
        local ok, err, exists = nil, nil, nil
        
        if isRedisOn then
            if ipBlockTimeout > 0 then
                local key = "black_ip:" .. ip
                exists = redisCli.redisGet(key)
                if not exists then
                    ok, err = redisCli.redisSet(key, 1, ipBlockTimeout)
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
                ok, err = blackip:set(ip, 1, ipBlockTimeout)
            end
        end

        if ok then
            local hostLogger = loggerFactory.getLogger(logPath .. "ipBlock.log", 'ipBlock', false)
            hostLogger:log(ngx.localtime() .. " " .. ip .. "\n")
            
            if ipBlockTimeout == 0 then
                local ipBlackLogger = loggerFactory.getLogger(rulePath .. "ipBlackList", 'ipBlack', false)
                ipBlackLogger:log(ip .. "\n")
            end
        end

        return ok
    end
end

function _M.doAction(ruleTable, logType, data, status)
    local rule = ruleTable.rule
    local action = toUpper(ruleTable.action)
    
    if action == "ALLOW" then
        writeLog(logType, data, rule, "ALLOW")
    elseif action == "DENY" then
        writeLog(logType, data, rule, "DENY")
        deny(status)
    elseif action == "REDIRECT" then
        writeLog(logType, data, rule, "REDIRECT")
        redirect()
    end
end

return _M