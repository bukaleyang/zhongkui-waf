local config = require("config")
local lib = require("lib")
local ipUtils = require("ip")
local cjson = require("cjson")
local toLower = string.lower
local remove = table.remove
local insert = table.insert
local pairs = pairs
local match = string.match

local rulePath = config.get("rulePath")
local function readRule(ruleFile)
	local file = io.open(rulePath .. ruleFile .. ".json", "r")
	if file == nil then
        return
	end

    local ruleTable = {}
    local text = file:read('*a')

	file:close()

    if #text > 0 then
        local result = cjson.decode(text)

        if result then
            local t = result["rules"]
            for k, r in pairs(t) do
                if toLower(r.state) == 'on' then
                    insert(ruleTable, r)
                end
            end
        end
    end

	return ruleTable
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
ccCount = tonumber(match(config.get("CCRate"), "(.*)/"))
ccSeconds = tonumber(match(config.get("CCRate"), "/(.*)"))
ipBlockTimeout = config.get("ipBlockTimeout") == nil and 0 or tonumber(config.get("ipBlockTimeout"))


urlRules = readRule("url")
argRules = readRule("args")
whiteURLRules = readRule("whiteUrl")
postRules = readRule("post")
cookieRules = readRule("cookie")
uaRules = readRule("user-agent")
headerRules = readRule("headers")

ipBlackList_subnet, ipBlackList = ipUtils.mergeAndSort(config.get("ipBlackList"), readFile("ipBlackList"))

ipWhiteList = ipUtils.initIpList(config.get("ipWhiteList"))
