local config = require("config")
local redisCli = require("redisCli")
local decoder = require("decoder")
local loggerFactory = require("loggerFactory")

local _M = {}

local logPath = config.get("logPath")

local blackIPLoaded = false

local methodWhiteList = config.get("methodWhiteList")

-- whether or not the regular expression matches on the input
local function matches(input, regex, options, ctx, nth)
    
    if not options then
        options = "isjo"
    end
    
    if not nth then
        nth = 0
    end

    return ngx.re.find(input, regex, options, ctx, nth)
end


local function matchRule(ruleTab, str, options)
	if str == nil or next(ruleTab) == nil then
        return false
	end

    for k,rule in ipairs(ruleTab) do
        if matches(str, rule, options) then
            return true, rule
		end
	end

	return false
end


-- Load the ip blacklist in the configuration file and log file to the ngx.shared.dict_blackip or Redis
function loadIPBlackList()
    if isRedisOn then
        if ipBlockTimeout > 0 then
            for k,ip in ipairs(ipBlackList) do
                redisCli.redisSet("black_ip:" .. ip, 1, ipBlockTimeout)
            end
        else
            for k,ip in ipairs(ipBlackList) do
                redisCli.redisBFAdd(ip)
            end
        end
    else
        local blackip = ngx.shared.dict_blackip
        for k,ip in ipairs(ipBlackList) do
            blackip:set(ip, 1, ipBlockTimeout)
	    end
        
        if ipBlockTimeout == 0 then
            local file = io.open(logPath .. "ipBlock.log", "r")
            if file then
                local ip
                for line in file:lines() do
                    ip = string.sub(line, 21)
                    ip = string.gsub(ip, "%s", "")
                    blackip:set(ip, 1)
                end
                file:close()
            end
        end
    end
end


function writeFile(fileName, value)
	local file = io.open(fileName, "a+")

	if file == nil or value == nil then
		return
	end

	file:write(value)
	file:flush()
	file:close()

	return
end

function getClientIP()
    local ip = ngx.var.remote_addr
    if ip == nil then
        ip = "unknown"
    end
    ngx.ctx.ip = ip
    return ip 
end

function writeLog(logType,data,rule,action)
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

function deny(status)
    if isProtectionMode then
        local statusCode = ngx.HTTP_FORBIDDEN
        if status then
            statusCode = status
        end
        
        ngx.status = statusCode
        return ngx.exit(ngx.status)
    end
end

function redirect()
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

-- Returns true if the client ip is in the whiteList,otherwise false
function isWhiteIp()
    if isWhiteIPOn then
        local ip = ngx.ctx.ip
	    if ip == "unknown" then
            return false
	    end

	    for k,v in ipairs(config.get("ipWhiteList")) do
	        if ip == v then
                local method_name = ngx.req.get_method()
                writeLog("whiteip", "-", "whiteip", "ALLOW")
		        return true
		    end
	    end
    end
    
    return false
end

-- Returns true if the client ip is in the blackList,otherwise false
function isBlackIp()
    if not blackIPLoaded then
       loadIPBlackList()
       blackIPLoaded = true
    end
    
    local ip = ngx.ctx.ip
	if ip == "unknown" then
        return false
    end
    
    local exists = false
    
    if isRedisOn then
        if ipBlockTimeout > 0 then
            exists = redisCli.redisGet("black_ip:" .. ip)
        else
            exists = redisCli.redisBFExists(ip)
        end
    else
        local blackip = ngx.shared.dict_blackip
        exists = blackip:get(ip)
    end

    if exists or ngx.ctx.geoip.isAllowed == false then
        writeLog("blackip", "-", "blackip", "DENY")
        deny()
        exists = true
    end

	return exists
end

-- block ip
function blockIp(ip)
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
        end

        return ok
    end
end

function isUnsafeHttpMethod()
    local method_name = ngx.req.get_method()

    for k,m in ipairs(methodWhiteList) do
	    if method_name == m then
		    return false
		end
	end

    writeLog("unsafe-method", method_name, "unsafe http method", "DENY")
    deny()
    return true
end

function isBlackUA()
    local ua = ngx.var.http_user_agent
    
    local m,rule = matchRule(uaRules, ua)
    if m then
        writeLog("ua", "-", rule, "DENY")
        deny()
		return true
    end
    
    return false
end

function isCC()
    if isCCDenyOn then
        local uri = ngx.var.uri
        local ip = ngx.ctx.ip
        local token = ngx.md5(ip .. uri)
        
        if isRedisOn then
            local prefix = "cc_req_count:"
            local count = redisCli.redisGet(prefix .. token)
            if not count then
                redisCli.redisSet(prefix .. token, 1, ccSeconds)
            elseif tonumber(count) > ccCount then
                writeLog("cc", "-", "cc", "DENY")
                blockIp(ip)
                deny(503)
                return true
            else
                redisCli.redisIncr(prefix .. token)
            end
        else
            local limit = ngx.shared.dict_cclimit
            local count,_ = limit:get(token)
            if not count then
                limit:set(token, 1, ccSeconds)
            elseif count > ccCount then
                writeLog("cc", "-", "cc", "DENY")
                blockIp(ip)
                deny(503)
                return true
            else
                limit:incr(token, 1)
            end
        end
    end
    return false
end

-- Returns true if the whiteURL rule is matched, otherwise false
function isWhiteURL()
    if isWhiteURLOn then
        local url = ngx.var.uri
        if url == nil or url == "" then
            return false
        end
        local m,rule = matchRule(whiteURLRules, url)
        if m then
            writeLog("whiteurl", "-", rule, "ALLOW")
		    return true
        end
        return false
    end
    
	return false
end

-- Returns true if the url rule is matched, otherwise false
function isBlackURL()
    if isBlackURLOn then
        local url = ngx.var.uri
        if url == nil or url == "" then
            return false
        end

        local m,rule = matchRule(urlRules, url)
        if m then
            writeLog("blackurl", "-", rule, "REDIRECT")
            redirect()
            return true
        end
    end
	return false
end


function isEvilArgs()
    local args = ngx.req.get_uri_args()
    if args then
        for key, val in pairs(args) do
            local vals = val
            if type(val) == "table" then
                vals = table.concat(val, ", ")
            end
            
            if vals and type(vals) ~= "boolean" and vals ~="" then
                local m,rule = matchRule(argRules, decoder.unescapeUri(vals))
                if m then
                    writeLog("args", "-", rule, "REDIRECT")
                    redirect()
                    return true
                end
            end
        end
    end
    return false
end

function isEvilHeaders()
    local referer = ngx.var.http_referer
    
    if referer and referer ~= "" then
        ua = decoder.decodeBase64(referer)
        local m,rule = matchRule(headerRules, referer)
        if m then
            writeLog("header-referer", "-", rule, "DENY")
            deny()
            return true
        end
    end
    
    local ua = ngx.var.http_user_agent
    if ua and ua ~= "" then
        ua = decoder.decodeBase64(ua)
        local m,rule = matchRule(headerRules, ua)
        if m then
            writeLog("header-ua", "-", rule, "DENY")
            deny()
            return true
        end
    end
    
    return false
end

function isBlackFileExt(ext)
    if ext == nil then
        return false
    end

    for k,v in ipairs(config.get("fileExtBlackList")) do
        if ext == v then
            local method_name = ngx.req.get_method()
            writeLog("file-ext", "-", ext, "REDIRECT")
            redirect()
            return true
        end
    end
    
    return false
end

function isEvilFile(body)
    local m, rule = matchRule(postRules, body)
    if m then
        writeLog("request_body", "[" .. body .. "]", rule, "DENY")
        deny()
        return true
    end
    
    return false
end

function isEvilBody(body)
    local m, rule = matchRule(postRules, body)
    if m then
        writeLog("request_body", "[" .. body .. "]", rule, "DENY")
        deny()
        return true
    end
    
    return false
end

function isEvilReqBody()
    if isRequestBodyOn then
        local method = ngx.req.get_method()
        
        local contentType = ngx.var.http_content_type
        local contentLength = tonumber(ngx.var.http_content_length)
        local boundary = nil
        
        if contentType then
            local bfrom,bto = matches(contentType, "\\s*boundary\\s*=(\\S+)", "isjo", nil, 1)
            if bfrom then
                boundary = string.sub(contentType, bfrom, bto)
            end
        end
        
        -- form-data
        if boundary then
            local sock, erro = ngx.req.socket()
            local size = 0
            ngx.req.init_body(128 * 1024)  -- buffer is 128KB
            
            local delimiter = '--' .. boundary
            local delimiterEnd = '--' .. boundary .. '--'
            
            local values = ''
            local isFile = false
            local files = {}
            
            while size < contentLength do
                local line, err, partial = sock:receive()
                if line == nil or err then
                    break
                end
                
                if line == delimiter or line == delimiterEnd then
                    if values ~= '' then
                        values = string.sub(values, 1, -2)
                        if isFile then
                            if isFileContentOn then
                                -- 文件内容检查
                                if isEvilFile(values) then
                                    return true
                                end
                            end
                            isFile = false
                        else
                            if isEvilBody(values) then
                                return true
                            end
                        end
                        values = ''
                    end
                elseif line ~='' then

                    if isFile then
                        if values == '' then
                            local fr = matches(line, "Content-Type:\\s*\\S+/\\S+", "ijo")
                            if fr == nil then
                                values = values .. line .. '\n'
                            end
                        else
                            values = values .. line .. '\n'
                        end
                    else
                        local from, to = matches(line, [[Content-Disposition:\s*form-data;[\s\S]+filename=["|'][\s\S]+\.(\w+)(?:"|')]], "ijo", nil, 1)
                        
                        if from then
                            local ext = string.sub(line, from, to)
                        
                            if isBlackFileExt(ext) then
                               return true 
                            end
                            
                            isFile = true
                        else
                            local fr = matches(line, "Content-Disposition:\\s*form-data;\\s*name=", "ijo")
                            if fr == nil then
                                values = values .. line .. '\n'
                            end
                        end
                    end
                    
                end
                size = size + string.len(line)
                ngx.req.append_body(line .. '\n')
            end
            
            ngx.req.finish_body()
        else
            -- application/x-www-form-urlencoded
            ngx.req.read_body()
            local args, err = ngx.req.get_post_args()
            
            if args then
                for key, val in pairs(args) do
                    local vals = val
                    if type(val) == "table" then
                        vals = table.concat(val, ", ")
                    end
                    
                    if vals and type(vals) ~= "boolean" and vals ~="" then
                        if isEvilBody(vals) then
                            return true
                        end
                    end
                end
            end    
        end
        return false
    end
    return false
end

function isEvilCookies()
    local cookie = ngx.var.http_cookie
    if isCookieOn and cookie then
        local m,rule = matchRule(cookieRules, cookie)
        if m then
            writeLog("cookie", "-", rule, "DENY")
            deny()
            return true
        end
    end
    return false
end

return _M