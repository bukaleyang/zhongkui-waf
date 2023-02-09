local config = require("config")
local lib = require("lib")

local rulePath = config.get("rulePath")
local function readRule(ruleFile)
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

isWAFOn = config.isOptionOn("waf")
isAttackLogOn = config.isOptionOn("attackLog")
isAutoIpBlockOn = config.isOptionOn("autoIpBlock")
isGeoIPOn = config.isOptionOn("geoip")
isWhiteURLOn = config.isOptionOn("whiteURL")
isBlackURLOn = config.isOptionOn("blackURL")
isWhiteIPOn = config.isOptionOn("whiteIP")
isBlackIPOn = config.isOptionOn("blackIP")
isCCDenyOn = config.isOptionOn("CCDeny")
isRequestBodyOn = config.isOptionOn("requestBodyCheck")
isFileContentOn = config.isOptionOn("fileContentCheck")
isCookieOn = config.isOptionOn("cookie")
isRedirectOn = config.isOptionOn("redirect")
isRedisOn = config.isOptionOn("redis")
isProtectionMode = (config.get("mode") == "protection" and true or false)
ccCount = tonumber(string.match(config.get("CCRate"), "(.*)/"))
ccSeconds = tonumber(string.match(config.get("CCRate"), "/(.*)"))
ipBlockTimeout = config.get("ipBlockTimeout") == nil and 0 or tonumber(config.get("ipBlockTimeout"))


urlRules = readRule("url")
argRules = readRule("args")
whiteURLRules = readRule("whiteUrl")
postRules = readRule("post")
cookieRules = readRule("cookie")
uaRules = readRule("user-agent")
headerRules = readRule("headers")

ipBlackList = readRule("ipBlackList")
