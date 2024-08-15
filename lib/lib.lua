-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local config = require "config"
local redisCli = require "redisCli"
local decoder = require "decoder"
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

local lower = string.lower
local upper = string.upper
local sub = string.sub
local trim = stringutf8.trim
local unescapeUri = decoder.unescapeUri

local concat = table.concat
local ngxgmatch = ngx.re.gmatch
local ngxfind = ngx.re.find
local md5 = ngx.md5

local is_system_option_on = config.is_system_option_on
local is_site_option_on = config.is_site_option_on
local get_site_config = config.get_site_config
local get_site_security_modules = config.get_site_security_modules
local get_system_config = config.get_system_config

local _M = {}

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
    if is_site_option_on("whiteIP") then
        local ip = ngx.ctx.ip
        if ip == "unknown" then
            return false
        end

        --local module = get_site_security_modules("whiteIp")
        if ipGroupMatch(constants.KEY_IP_GROUPS_WHITELIST, ip) then
            -- doAction(module.moduleName, module.rules[1])
            ngx.status = ngx.OK
            return ngx.exit(ngx.status)
        end
    end
end

-- Returns true if the client ip is in the blackList,otherwise false
function _M.isBlackIp()
    if is_site_option_on("blackIP") then
        local ip = ngx.ctx.ip
        if ip == "unknown" then
            return false
        end

        local exists = nil

        if ngx.ctx.geoip.is_allowed == false then
            exists = true
        else
            if is_system_option_on("redis") then
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
            local module = get_site_security_modules("blackIp")
            doAction(module.moduleName, module.rules[1])
        end
    end
end

function _M.isUnsafeHttpMethod()
    if is_site_option_on("httpMethod") then
        local method_name = upper(ngx.req.get_method())

        local module = get_site_security_modules("httpMethod")
        for _, r in pairs(module.rules) do
            if method_name == r.rule then
                doAction(module.moduleName, r, method_name)
                break
            end
        end
    end
end

function _M.isBot()
    if is_site_option_on("bot") then
        if cc.checkAccessToken() then
            return false
        end

        local ip = ngx.ctx.ip
        local trap = get_site_config("bot").trap
        if trap.state == "on" then
            local ruri = ngx.var.request_uri
            local uri = ngx.var.uri

            if uri == trap.uri or ruri == trap.uri then
                local module = get_site_security_modules("botTrap")
                local ruleTab = module.rules[1]
                blockIp(ip, ruleTab)
                doAction(module.moduleName, ruleTab)
                return true
            end
        end

        local ua = ngx.ctx.ua

        local module = get_site_security_modules("user-agent")
        local m, ruleTable = matchRule(module.rules, ua)
        if m then
            blockIp(ip, ruleTable)
            doAction(module.moduleName, ruleTable)
            return true
        end
    end
end

function _M.isCC()
    if is_site_option_on("cc") then
        if cc.checkAccessToken() then
            return false
        end

        local ip = ngx.ctx.ip

        local module = get_site_security_modules("cc")
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
                if is_system_option_on("redis") then
                    key = "cc_req_count:" .. key
                    local count, _ = redisCli.redisIncr(key, ruleTab.duration)
                    if not count then
                        redisCli.redisSet(key, 1, ruleTab.duration)
                    elseif count > ruleTab.threshold then
                        if count >= (get_site_config("cc").maxFailTimes + ruleTab.threshold) then
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
                        if count >= (get_site_config("cc").maxFailTimes + ruleTab.threshold) then
                            blockIp(ip, ruleTab)
                        end
                        doAction(module.moduleName, ruleTab, nil, ruleTab.rule, 503)

                        return true
                    end
                end
            end
        end
    end
end

function _M.isACL()
    if is_site_option_on("acl") then
        local module = get_site_security_modules("acl")
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
    end
end

-- Returns true if the whiteURL rule is matched, otherwise false
function _M.isWhiteURL()
    if is_site_option_on("whiteUrl") then
        local url = ngx.var.uri
        if url == nil or url == "" then
            return false
        end
        local module = get_site_security_modules("whiteUrl")
        local m, ruleTable = matchRule(module.rules, url)
        if m then
            doAction(module.moduleName, ruleTable)
            return true
        end
        return false
    end
end

-- Returns true if the url rule is matched, otherwise false
function _M.isBlackURL()
    if is_site_option_on("blackUrl") then
        local url = ngx.var.uri
        if url == nil or url == "" then
            return false
        end

        local module = get_site_security_modules("blackUrl")
        local m, ruleTable = matchRule(module.rules, url)
        if m then
            doAction(module.moduleName, ruleTable)
            return true
        end
    end
    return false
end

function _M.isEvilArgs()
    if is_site_option_on("args") then
        local args = ngx.req.get_uri_args()
        if args then
            for _, val in pairs(args) do
                local vals = val
                if type(val) == "table" then
                    vals = concat(val, ", ")
                end

                if vals and type(vals) ~= "boolean" and vals ~= "" then
                    vals = unescapeUri(vals)
                    local module = get_site_security_modules("args")
                    local m, ruleTable = matchRule(module.rules, vals)
                    if m then
                        doAction(module.moduleName, ruleTable)
                        return true
                    end
                    _M.isSqliOrXss(vals)
                end
            end
        end
    end
end

function _M.isEvilHeaders()
    if is_site_option_on("headers") then
        local module = get_site_security_modules("headers")
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
    end
end

function _M.isBlackFileExt(ext, line)
    if is_site_option_on("fileExt") then
        if ext == nil then
            return
        end
        ext = lower(ext)

        local module = get_site_security_modules("fileExt")
        for _, r in ipairs(module.rules) do
            if ext == lower(r.rule) then
                if is_system_option_on("attackLog") and get_system_config("attackLog").jsonFormat.state == "off" then
                    line = "[" ..  line .. "]"
                end
                doAction(module.moduleName, r, line)
                break
            end
        end
    end
end

function _M.isEvilFile(body)
    local module = get_site_security_modules("post")
    local m, ruleTable = matchRule(module.rules, body)
    if m then
        doAction(module.moduleName, ruleTable)
        return true
    end

    return false
end

function _M.isEvilBody(body)
    local module = get_site_security_modules("post")
    local m, ruleTable = matchRule(module.rules, body)
    if m then
        doAction(module.moduleName, ruleTable)
        return true
    end

    return false
end

function _M.isEvilReqBody()
    if is_site_option_on("post") then
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
                            if is_site_option_on("fileContentCheck") then
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
                        vals = concat(val, ", ")
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
    end
end

function _M.isEvilCookies()
    local cookie = ngx.var.http_cookie
    if is_site_option_on("cookie") and cookie then
        local module = get_site_security_modules("cookie")
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
        local is_sqli_on = is_site_option_on("sqli")
        local is_xss_on = is_site_option_on("xss")
        if not is_sqli_on and not is_xss_on then
            return
        end

        if type(data) ~= 'table' then
            local t = {}
            t[1] = tostring(data)
            data = t
        end

        local module_sqli = get_site_security_modules("sqli")
        local module_xss = get_site_security_modules("xss")
        local rule_sqli = module_sqli.rules[1]
        local rule_xss = module_xss.rules[1]

        for _, v in pairs(data) do
            if type(v) == 'string' then
                if is_sqli_on then
                    local is_sqli = libinjection.sqli(v)
                    if is_sqli then
                        doAction(module_sqli.moduleName, rule_sqli)
                        return true
                    end
                end

                if is_xss_on then
                    local is_xss = libinjection.xss(v)
                    if is_xss then
                        doAction(module_xss.moduleName, rule_xss)
                        return true
                    end
                end
            end
        end
    end
end

return _M
