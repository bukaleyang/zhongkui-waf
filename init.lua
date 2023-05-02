local config = require "config"
local lib = require "lib"
local file = require "file"
local ipUtils = require "ip"
local cjson = require "cjson"

local readRule = file.readRule
local readFileToString = file.readFileToString
local readFileToTable = file.readFileToTable

local dict_config = ngx.shared.dict_config
local rulesConfig = {}

local rulePath = config.get("rulePath")

config.isWAFOn = config.isOptionOn("waf")
config.isAttackLogOn = config.isOptionOn("attackLog")
config.isGeoIPOn = config.isOptionOn("geoip")
config.isWhiteURLOn = config.isOptionOn("whiteURL")
config.isBlackURLOn = config.isOptionOn("blackURL")
config.isWhiteIPOn = config.isOptionOn("whiteIP")
config.isBlackIPOn = config.isOptionOn("blackIP")
config.isCCDefenceOn = config.isOptionOn("cc_defence")
config.isRequestBodyOn = config.isOptionOn("requestBodyCheck")
config.isFileContentOn = config.isOptionOn("fileContentCheck")
config.isCookieOn = config.isOptionOn("cookie")
config.isRedirectOn = config.isOptionOn("redirect")
config.isRedisOn = config.isOptionOn("redis")
config.isSensitiveDataFilteringOn = config.isOptionOn("sensitive_data_filtering")
config.isBotOn = config.isOptionOn("bot")

config.isProtectionMode = (config.get("mode") == "protection" and true or false)
config.ccMaxFailTimes = config.get("cc_max_fail_times") == nil and 5 or tonumber(config.get("cc_max_fail_times"))
config.ccActionTimeout = config.get("cc_action_timeout") == nil and 60 or tonumber(config.get("cc_action_timeout"))
config.ccAccessTokenTimeout = config.get("cc_accesstoken_timeout") == nil and 1800 or tonumber(config.get("cc_accesstoken_timeout"))
config.secret = config.get("secret")

config.isRulesSortOn = config.isOptionOn("rules_sort")
config.rulesSortPeriod = config.get("rules_sort_period") == nil and 60 or tonumber(config.get("rules_sort_period"))

config.ipBlackList_subnet, config.ipBlackList = ipUtils.mergeAndSort(config.get("ipBlackList"), readFileToTable(rulePath .. "ipBlackList"))
config.ipWhiteList = ipUtils.initIpList(config.get("ipWhiteList"))

rulesConfig.blackUrl = readRule(rulePath, "blackUrl")
rulesConfig.args = readRule(rulePath, "args")
rulesConfig.whiteUrl = readRule(rulePath, "whiteUrl")
rulesConfig.post = readRule(rulePath, "post")
rulesConfig.cookie = readRule(rulePath, "cookie")
rulesConfig.headers = readRule(rulePath, "headers")
rulesConfig.cc = readRule(rulePath, "cc")
rulesConfig.sensitive, rulesConfig.sensitiveWords = readRule(rulePath, "sensitive")
rulesConfig["user-agent"] = readRule(rulePath, "user-agent")

rulesConfig.fileExt = {ruleType = "file-ext", rule = "file-ext", action = "REDIRECT"}
rulesConfig.whiteIp = {ruleType = "whiteip", rule = "whiteip", action = "ALLOW"}
rulesConfig.blackIp = {ruleType = "blackip", rule = "blackip", action = "DENY"}
rulesConfig.unsafeMethod = {ruleType = "unsafe-method", rule = "unsafe http method", action = "DENY"}

local jsonStr = cjson.encode(rulesConfig)
dict_config:set("rules", jsonStr)

config.rules = rulesConfig
config.html = readFileToString(config.get("redirect_html"))
