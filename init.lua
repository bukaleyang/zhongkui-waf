local config = require "config"
local lib = require "lib"
local ipUtils = require "ip"
local cjson = require "cjson"
local toLower = string.lower
local remove = table.remove
local insert = table.insert
local pairs = pairs
local match = string.match

local dict_config = ngx.shared.dict_config
local rulesConfig = {}

local rulePath = config.get("rulePath")
local function readRule(ruleFile)
	local file = io.open(rulePath .. ruleFile .. ".json", "r")
	if file == nil then
        return
	end

    local rulesTable = {}
    local text = file:read('*a')

	file:close()

    if #text > 0 then
        local result = cjson.decode(text)

        if result then
            local t = result["rules"]
            for k, r in pairs(t) do
                if toLower(r.state) == 'on' then
                    r.ruleType = ruleFile
                    r.hits = 0
                    r.totalHits = 0
                    insert(rulesTable, r)
                end
            end
        end
    end

    rulesConfig[ruleFile] = rulesTable
	return rulesTable
end

local function readFile(ruleFile)
	local file = io.open(rulePath .. ruleFile, "r")
	if file == nil then
        return
	end
    local t = {}

	for line in file:lines() do
        line = string.gsub(line, "[\r\n]", "")
        table.insert(t, line)
	end

	file:close()

	return t
end

config.isWAFOn = config.isOptionOn("waf")
config.isAttackLogOn = config.isOptionOn("attackLog")
config.isAutoIpBlockOn = config.isOptionOn("autoIpBlock")
config.isGeoIPOn = config.isOptionOn("geoip")
config.isWhiteURLOn = config.isOptionOn("whiteURL")
config.isBlackURLOn = config.isOptionOn("blackURL")
config.isWhiteIPOn = config.isOptionOn("whiteIP")
config.isBlackIPOn = config.isOptionOn("blackIP")
config.isCCDenyOn = config.isOptionOn("CCDeny")
config.isRequestBodyOn = config.isOptionOn("requestBodyCheck")
config.isFileContentOn = config.isOptionOn("fileContentCheck")
config.isCookieOn = config.isOptionOn("cookie")
config.isRedirectOn = config.isOptionOn("redirect")
config.isRedisOn = config.isOptionOn("redis")
config.isProtectionMode = (config.get("mode") == "protection" and true or false)
config.ccCount = tonumber(match(config.get("CCRate"), "(.*)/"))
config.ccSeconds = tonumber(match(config.get("CCRate"), "/(.*)"))
config.ipBlockTimeout = config.get("ipBlockTimeout") == nil and 0 or tonumber(config.get("ipBlockTimeout"))
config.isRulesSortOn = config.isOptionOn("rules_sort")
config.rulesSortPeriod = config.get("rules_sort_period") == nil and 60 or tonumber(config.get("rules_sort_period"))

local urlRules = readRule("blackUrl")
local argRules = readRule("args")
local whiteURLRules = readRule("whiteUrl")
local postRules = readRule("post")
local cookieRules = readRule("cookie")
local uaRules = readRule("user-agent")
local headerRules = readRule("headers")

config.ipBlackList_subnet, config.ipBlackList = ipUtils.mergeAndSort(config.get("ipBlackList"), readFile("ipBlackList"))

config.ipWhiteList = ipUtils.initIpList(config.get("ipWhiteList"))


rulesConfig.fileExt = {ruleType = "file-ext", rule = "file-ext", action = "REDIRECT"}
rulesConfig.whiteIp = {ruleType = "whiteip", rule = "whiteip", action = "ALLOW"}
rulesConfig.blackIp = {ruleType = "blackip", rule = "blackip", action = "DENY"}
rulesConfig.unsafeMethod = {ruleType = "unsafe-method", rule = "unsafe http method", action = "DENY"}
rulesConfig.cc = {ruleType = "cc", rule = "cc", action = "DENY"}

local jsonStr = cjson.encode(rulesConfig)
dict_config:set("rules", jsonStr)

config.rules = rulesConfig
