-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local config = require "config"
local redisCli = require "redisCli"
local decoder = require "decoder"
local ipUtils = require "ip"
local action = require "action"
local cc = require "cc"
local stringutf8 = require "stringutf8"
local request = require "request"
local ck = require "resty.cookie"
local libinjection = require "resty.libinjection"
local nkeys = require "table.nkeys"
local constants = require "constants"

local blockIp = action.blockIp
local doAction = action.doAction
local ipairs, pairs = ipairs, pairs
local type = type
local md5 = ngx.md5
local lower = string.lower
local sub = string.sub
local trim = stringutf8.trim

local concat = table.concat
local ngxgmatch = ngx.re.gmatch
local ngxfind = ngx.re.find

local _M = {}

local methodWhiteList = config.get("methodWhiteList")

-- whether or not the regular expression matches on the input
local function matches(input, regex, options, ctx, nth)
    if not options then
        options = "isjo"
    end

    if not nth then
        nth = 0
    end

    return ngxfind(input, regex, options, ctx, nth)
end


local function matchRule(ruleTab, str, options)
    if str == nil or next(ruleTab) == nil then
        return false
    end

    for _, t in ipairs(ruleTab) do
        if matches(str, t.rule, options) then
            return true, t
        end
    end

    return false
end

local function ipGroupMatch(group, ip)
    local matcher = config.ipgroups[group]
    if matcher then
        return matcher:match(ip)
    end

    return false
end

function _M.isWhiteIp()
    if config.isWhiteIPOn then
        local ip = ngx.ctx.ip
        if ip == "unknown" then
            return false
        end

        --local module = config.securityModules.whiteIp

        if ipGroupMatch(constants.KEY_IP_GROUPS_WHITELIST, ip) then
            -- doAction(module.moduleName, module.rules[1])
            ngx.status = ngx.OK
            return ngx.exit(ngx.status)
        end
    end
end

-- Returns true if the client ip is in the blackList,otherwise false
function _M.isBlackIp()
    if config.isBlackIPOn then

        local ip = ngx.ctx.ip
        if ip == "unknown" then
            return false
        end

        local exists = nil

        if ngx.ctx.geoip.isAllowed == false then
            exists = true
        else
            if config.isRedisOn then
                exists = redisCli.redisGet(constants.KEY_BLACKIP_PREFIX .. ip)
            else
                local blackip = ngx.shared.dict_blackip
                exists = blackip:get(ip)
            end
        end

        if not exists then
            if ipGroupMatch(constants.KEY_IP_GROUPS_BLACKLIST, ip) then
                exists = true
            end
        end

        if exists then
            local module = config.securityModules.blackIp
            doAction(module.moduleName, module.rules[1])
        end
    end
end

function _M.isUnsafeHttpMethod()
    local method_name = ngx.req.get_method()

    for _, m in ipairs(methodWhiteList) do
        if method_name == m then
            return false
        end
    end

    local module = config.securityModules.unsafeMethod
    doAction(module.moduleName, module.rules[1])
    return true
end

function _M.isBot()
    if config.isBotOn then
        if cc.checkAccessToken() then
            return false
        end

        local ip = ngx.ctx.ip

        if config.isBotTrapOn then
            local ruri = ngx.var.request_uri
            local uri = ngx.var.uri

            if uri == config.botTrapUri or ruri == config.botTrapUri then
                local module = config.securityModules.botTrap
                local ruleTab = module.rules[1]
                blockIp(ip, ruleTab)
                doAction(module.moduleName, ruleTab)
                return true
            end
        end

        local ua = ngx.ctx.ua

        local module = config.securityModules["user-agent"]
        local m, ruleTable = matchRule(module.rules, ua)
        if m then
            blockIp(ip, ruleTable)
            doAction(module.moduleName, ruleTable)
            return true
        end
    end
    return false
end

function _M.isCC()
    if config.isCCDefenceOn then
        if cc.checkAccessToken() then
            return false
        end

        local ip = ngx.ctx.ip

        local module = config.securityModules.cc
        local rules = module.rules
        for _, ruleTab in pairs(rules) do
            local countType = lower(ruleTab.countType)
            local pattern = ruleTab.pattern
            local match = true
            local matchData = nil
            local key = ""
            if countType == "url" then
                local url = ngx.var.uri
                key = ip .. md5(url)
                matchData = url
            elseif countType == "ip" then
                key = ip
                matchData = ip
            end

            if pattern and pattern ~= "" then
                if not matches(matchData, ruleTab.pattern) then
                    match = false
                end
            end

            if match then
                if config.isRedisOn then
                    key = "cc_req_count:" .. key
                    local count, _ = redisCli.redisIncr(key, ruleTab.duration)
                    if not count then
                        redisCli.redisSet(key, 1, ruleTab.duration)
                    elseif count > ruleTab.threshold then
                        if count >= (config.ccMaxFailTimes + ruleTab.threshold) then
                            blockIp(ip, ruleTab)
                        end
                        doAction(module.moduleName, ruleTab, nil, ruleTab.rule, 503)

                        return true
                    end
                else
                    local limit = ngx.shared.dict_cclimit
                    local count, _ = limit:incr(key, 1, 0, ruleTab.duration)
                    if not count then
                        limit:set(key, 1, ruleTab.duration)
                    elseif count > ruleTab.threshold then
                        if count >= (config.ccMaxFailTimes + ruleTab.threshold) then
                            blockIp(ip, ruleTab)
                        end
                        doAction(module.moduleName, ruleTab, nil, ruleTab.rule, 503)

                        return true
                    end
                end
            end
        end
    end

    return false
end

function _M.isACL()
    local module = config.securityModules.acl
    local rules = module.rules
    if rules == nil or nkeys(rules) == 0 then
        return false
    end

    for _, ruleTab in pairs(rules) do
        local conditions = ruleTab.conditions
        local match = true
        for _, condition in pairs(conditions) do
            local field = condition.field
            local fieldName = condition.name
            local pattern = condition.pattern
            local matchValue = ''
            if field == 'URL' then
                matchValue = ngx.var.request_uri
            elseif field == 'Cookie' then
                if fieldName ~= nil and fieldName ~= '' then
                    local cookies = ck:new()
                    if not cookies then
                        match = false
                        break
                    else
                        matchValue = cookies:get(fieldName)
                    end
                else
                    matchValue = ngx.var.http_cookie
                end
            elseif field == 'Header' then
                local headers = ngx.req.get_headers()
                if headers then
                    if fieldName ~= nil and fieldName ~= '' then
                        matchValue = headers[fieldName]
                    else
                        matchValue = concat(headers, '')
                    end
                else
                    match = false
                    break
                end
            elseif field == 'Referer' then
                matchValue = ngx.var.http_referer
            elseif field == 'User-Agent' then
                matchValue = ngx.var.http_user_agent
            elseif field == 'IP' then
                local ip = ngx.ctx.ip
                local operator = condition.operator
                local ipGroupId = condition.ipGroupId
                if operator == 'in' then
                    if ipGroupMatch(ipGroupId, ip) == false then
                        match = false
                        break
                    end
                elseif operator == 'notin' then
                    if ipGroupMatch(ipGroupId, ip) then
                        match = false
                        break
                    end
                elseif operator == 'equal' then
                    matchValue = ip
                end
            end

            if pattern == '' then
                if matchValue ~= nil and matchValue ~= '' then
                    match = false
                    break
                end
            else
                if not matches(matchValue, pattern) then
                    match = false
                    break
                end
            end
        end

        if match then
            local ip = ngx.ctx.ip
            blockIp(ip, ruleTab)
            doAction(module.moduleName, ruleTab)
            return true
        end
    end

    return false
end

-- Returns true if the whiteURL rule is matched, otherwise false
function _M.isWhiteURL()
    if config.isWhiteURLOn then
        local url = ngx.var.uri
        if url == nil or url == "" then
            return false
        end
        local module = config.securityModules.whiteUrl
        local m, ruleTable = matchRule(module.rules, url)
        if m then
            doAction(module.moduleName, ruleTable)
            return true
        end
        return false
    end

    return false
end

-- Returns true if the url rule is matched, otherwise false
function _M.isBlackURL()
    if config.isBlackURLOn then
        local url = ngx.var.uri
        if url == nil or url == "" then
            return false
        end

        local module = config.securityModules.blackUrl
        local m, ruleTable = matchRule(module.rules, url)
        if m then
            doAction(module.moduleName, ruleTable)
            return true
        end
    end
    return false
end

function _M.isEvilArgs()
    local args = ngx.req.get_uri_args()
    if args then
        for _, val in pairs(args) do
            local vals = val
            if type(val) == "table" then
                vals = table.concat(val, ", ")
            end

            if vals and type(vals) ~= "boolean" and vals ~= "" then
                vals = decoder.unescapeUri(vals)
                local module = config.securityModules.args
                local m, ruleTable = matchRule(module.rules, vals)
                if m then
                    doAction(module.moduleName, ruleTable)
                    return true
                end
                _M.isSqliOrXss(vals)
            end
        end
    end
    return false
end

function _M.isEvilHeaders()
    local module = config.securityModules.headers
    local referer = ngx.var.http_referer
    if referer and referer ~= "" then
        local m, ruleTable = matchRule(module.rules, referer)
        if m then
            doAction(module.moduleName, ruleTable, referer)
            return true
        end
    end

    local ua = ngx.ctx.ua
    if ua and ua ~= "" then
        local m, ruleTable = matchRule(module.rules, ua)
        if m then
            doAction(module.moduleName, ruleTable)
            return true
        end
    end

    return false
end

function _M.isBlackFileExt(ext, line)
    if ext == nil then
        return false
    end

    local t = config.get("fileExtBlackList") or {}
    for _, v in ipairs(t) do
        if ext == v then
            if not config.isJsonFormatLogOn then
                line = "[" ..  line .. "]"
            end
            local module = config.securityModules.fileExt
            doAction(module.moduleName, module.rules[1], line)
            return true
        end
    end

    return false
end

function _M.isEvilFile(body)
    local module = config.securityModules.post
    local m, ruleTable = matchRule(module.rules, body)
    if m then
        doAction(module.moduleName, ruleTable)
        return true
    end

    return false
end

function _M.isEvilBody(body)
    local module = config.securityModules.post
    local m, ruleTable = matchRule(module.rules, body)
    if m then
        doAction(module.moduleName, ruleTable)
        return true
    end

    return false
end

function _M.isEvilReqBody()
    if config.isRequestBodyOn then
       -- local method = ngx.req.get_method()

        local contentType = ngx.var.http_content_type
        local boundary = request.getBoundary()

        -- form-data
        if boundary then
            local delimiter = '--' .. boundary
            local delimiterEnd = '--' .. boundary .. '--'

            local body = ''
            local isFile = false

            local bodyRaw = request.getRequestBody()
            local it, err = ngxgmatch(bodyRaw, ".+?(?:\n|$)", "isjo")
            if not it then
                ngx.log(ngx.ERR, "error: ", err)
                return
            end

            while true do
                local m, err = it()
                if err then
                    ngx.log(ngx.ERR, "error: ", err)
                    return
                end

                if not m then
                    break
                end

                local line = trim(m[0])
                if line == nil then
                    break
                end

                if line == delimiter or line == delimiterEnd then
                    if body ~= '' then
                        body = sub(body, 1, -2)
                        if isFile then
                            if config.isFileContentOn then
                                -- 文件内容检查
                                if _M.isEvilFile(body) then
                                    return true
                                end
                            end
                            isFile = false
                        else
                            if _M.isEvilBody(body) then
                                return true
                            end
                        end
                        body = ''
                    end
                elseif line ~= '' then
                    if isFile then
                        if body == '' then
                            local fr = matches(line, "Content-Type:\\s*\\S+/\\S+", "ijo")
                            if fr == nil then
                                body = body .. line .. '\n'
                            end
                        else
                            body = body .. line .. '\n'
                        end
                    else
                        local from, to = matches(line, [[Content-Disposition:\s*form-data;[\s\S]+filename=["|'][\s\S]+\.(\w+)(?:"|')]], "ijo", nil, 1)

                        if from then
                            local ext = sub(line, from, to)

                            if _M.isBlackFileExt(ext, line) then
                                return true
                            end

                            isFile = true
                        else
                            local fr = matches(line, "Content-Disposition:\\s*form-data;\\s*name=", "ijo")
                            if fr == nil then
                                body = body .. line .. '\n'
                            end
                        end
                    end
                end
            end
            _M.isSqliOrXss(bodyRaw)
        elseif matches(contentType, "\\s*x-www-form-urlencoded") then
            ngx.req.read_body()
            local args, err = ngx.req.get_post_args()

            if args then
                for _, val in pairs(args) do
                    local vals = val
                    if type(val) == "table" then
                        vals = table.concat(val, ", ")
                    end

                    if vals and type(vals) ~= "boolean" and vals ~= "" then
                        if _M.isEvilBody(vals) then
                            return true
                        end
                        _M.isSqliOrXss(vals)
                    end
                end
            end
        else
            local bodyRaw = request.getRequestBody()
            if bodyRaw and bodyRaw ~= "" then
                if _M.isEvilBody(bodyRaw) then
                    return true
                end
                _M.isSqliOrXss(bodyRaw)
            end
        end

        return false
    end

    return false
end

function _M.isEvilCookies()
    local cookie = ngx.var.http_cookie
    if config.isCookieOn and cookie then
        local module = config.securityModules.cookie
        local m, ruleTable = matchRule(module.rules, cookie)
        if m then
            doAction(module.moduleName, ruleTable)
            return true
        end
    end

    return false
end

function _M.isSqliOrXss(data)
    if data then
        if not config.isSqliOn and not config.isXssOn then
            return
        end

        if type(data) ~= 'table' then
            local t = {}
            t[1] = tostring(data)
            data = t
        end

        local sqliModule = config.securityModules.sqli
        local xssModule = config.securityModules.xss
        local sqliRule = sqliModule.rules[1]
        local xssRule = xssModule.rules[1]

        for _, v in pairs(data) do
            if type(v) == 'string' then
                if config.isSqliOn then
                    local isSqli = libinjection.sqli(v)
                    if isSqli then
                        doAction(sqliModule.moduleName, sqliRule)
                        return true
                    end
                end

                if config.isXssOn then
                    local isXss = libinjection.xss(v)
                    if isXss then
                        doAction(xssModule.moduleName, xssRule)
                        return true
                    end
                end
            end
        end
    end
end

return _M
