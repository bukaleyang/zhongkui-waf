local cjson = require "cjson"
local fileUtils = require "file"
local ipUtils = require "ip"
local stringutf8 = require "stringutf8"
local nkeys = require "table.nkeys"

local readRule = fileUtils.readRule
local readFileToString = fileUtils.readFileToString
local readFileToTable = fileUtils.readFileToTable

local ngxfind = ngx.re.find
local ngxmatch = ngx.re.match
local ngxgmatch = ngx.re.gmatch
local ngxsub = ngx.re.sub
local ngxgsub = ngx.re.gsub

local sub = string.sub
local trim = stringutf8.trim

local insert = table.insert

local pairs = pairs
local tonumber = tonumber

local _M = {}

local config = {}

local CONFIG_REGEX_SWITCH = "^\"?(?:on|off)\"?$"
local CONFIG_REGEX_PATH = "^\"?[\\s\\S]+\"?$"
local CONFIG_REGEX_NUMBER = "^[1-9]\\d*$"
local CONFIG_REGEX_ARRAY_IP = "^\\[[\\d\\./,\"\\s]*\\]$"
local CONFIG_REGEX_ACTION = "^\"?(?:allow|deny|redirect|coding|redirect_js|redirect_302)\"?$"

-- 配置项验证正则集合
local configRegex = {
    waf = CONFIG_REGEX_SWITCH,
    mode = "^\"?(?:protection|monitor)\"?$",
    rules_sort = CONFIG_REGEX_SWITCH,
    rules_sort_period = CONFIG_REGEX_NUMBER,
    attackLog = CONFIG_REGEX_SWITCH,
    attackLog_json_format = CONFIG_REGEX_SWITCH,
    logPath = CONFIG_REGEX_PATH,
    geoip = CONFIG_REGEX_SWITCH,
    geoip_db_file = "^\"?[^\\n\\v]+GeoLite2-City.mmdb\"?$",
    geoip_allow_country = "^\\[\\S*\\]$",
    geoip_language = "^\"?\\S+\"?$",
    whiteIP = CONFIG_REGEX_SWITCH,
    ipWhiteList = CONFIG_REGEX_ARRAY_IP,
    blackIP = CONFIG_REGEX_SWITCH,
    ipBlackList = CONFIG_REGEX_ARRAY_IP,
    whiteURL = CONFIG_REGEX_SWITCH,
    blackURL = CONFIG_REGEX_SWITCH,
    methodWhiteList = "^\\[\\S*\\]$",
    requestBodyCheck = CONFIG_REGEX_SWITCH,
    -- 上传文件类型黑名单
    fileExtBlackList = "^\\[\\S*\\]$",
    -- 上传文件内容检查
    fileContentCheck = CONFIG_REGEX_SWITCH,
    -- cookie检查
    cookie = CONFIG_REGEX_SWITCH,
    -- bot管理
    bot = CONFIG_REGEX_SWITCH,
    -- 开启bot陷阱
    bot_trap = CONFIG_REGEX_SWITCH,
    -- 陷阱URI，隐藏在页面中，对普通正常用户不可见，访问此URI的请求被视为bot，建议安装后修改
    bot_trap_uri = "^\"\"$|^\"?/\\S*\"?$",
    -- 被陷阱捕获后的处置动作
    bot_trap_action = CONFIG_REGEX_ACTION,
    -- 访问陷阱URI后屏蔽ip
    bot_trap_ip_block = CONFIG_REGEX_SWITCH,
    -- ip禁止访问时间，单位是秒，如果设置为0则永久禁止
    bot_trap_ip_block_timeout = "^\\d+$",
    -- cc攻击拦截
    cc_defence = CONFIG_REGEX_SWITCH,
    -- 浏览器验证失败几次后自动拉黑IP地址，需要将autoIpBlock设置为on
    cc_max_fail_times = CONFIG_REGEX_NUMBER,
    -- 处置动作超时时间，单位是秒
    cc_action_timeout = CONFIG_REGEX_NUMBER,
    -- 验证请求来自于真实浏览器后，浏览器cookie携带的访问令牌有效时间，单位是秒
    cc_accesstoken_timeout = CONFIG_REGEX_NUMBER,
    -- 密钥，用于请求签名等
    secret = "^\\S+$",
    -- 敏感数据脱敏
    sensitive_data_filtering = CONFIG_REGEX_SWITCH,
    -- Redis支持，打开后请求频率统计及ip黑名单将从Redis中存取
    redis = CONFIG_REGEX_SWITCH,
    redis_host = "^\"?\\S*\"?$",
    redis_port = CONFIG_REGEX_NUMBER,
    redis_passwd = "^\"\"$|^\"?\\S+\"?$",
    redis_ssl = "^(?:true|false)$",
    redis_pool_size = CONFIG_REGEX_NUMBER,
    -- Respectively sets the connect, send, and read timeout thresholds (in ms)
    redis_timeouts = "^\"?[1-9]\\d*,[1-9]\\d*,[1-9]\\d*\"?$",
    -- 是否重定向
    redirect = CONFIG_REGEX_SWITCH,
    -- 非法请求将重定向的html
    redirect_html = CONFIG_REGEX_PATH,
    -- 流量监控页面
    dashboard = CONFIG_REGEX_SWITCH
}

-- Returns true if the config option is "on",otherwise false
local function isOptionOn(option)
    return config[option] == "on" and true or false
end

-- 初始化配置项
local function initConfig()
    local dict_config = ngx.shared.dict_config
    local rulesConfig = {}

    local rulePath = _M.ZHONGKUI_PATH .. "/rules/"

    _M.isWAFOn = isOptionOn("waf")
    _M.isAttackLogOn = isOptionOn("attackLog")
    _M.isJsonFormatLogOn = isOptionOn("attackLog_json_format")
    _M.isGeoIPOn = isOptionOn("geoip")
    _M.isWhiteURLOn = isOptionOn("whiteURL")
    _M.isBlackURLOn = isOptionOn("blackURL")
    _M.isWhiteIPOn = isOptionOn("whiteIP")
    _M.isBlackIPOn = isOptionOn("blackIP")
    _M.isCCDefenceOn = isOptionOn("cc_defence")
    _M.isRequestBodyOn = isOptionOn("requestBodyCheck")
    _M.isFileContentOn = isOptionOn("fileContentCheck")
    _M.isCookieOn = isOptionOn("cookie")
    _M.isRedirectOn = isOptionOn("redirect")
    _M.isRedisOn = isOptionOn("redis")
    _M.isSensitiveDataFilteringOn = isOptionOn("sensitive_data_filtering")
    _M.isBotOn = isOptionOn("bot")
    _M.isDashboardOn = isOptionOn("dashboard")
    _M.isBotTrapOn = isOptionOn("bot_trap")
    _M.isBotTrapIpBlockOn = isOptionOn("bot_trap_ip_block")

    _M.isProtectionMode = (_M.get("mode") == "protection" and true or false)
    _M.ccMaxFailTimes = _M.get("cc_max_fail_times") == nil and 5 or tonumber(_M.get("cc_max_fail_times"))
    _M.ccActionTimeout = _M.get("cc_action_timeout") == nil and 60 or tonumber(_M.get("cc_action_timeout"))
    _M.ccAccessTokenTimeout = _M.get("cc_accesstoken_timeout") == nil and 1800 or tonumber(_M.get("cc_accesstoken_timeout"))
    _M.secret = _M.get("secret")
    _M.botTrapUri = _M.get("bot_trap_uri") or "/zhongkuiwaf/honey/trap"
    _M.botTrapIpBlockTimeout = tonumber(_M.get("bot_trap_ip_block_timeout")) or 60

    _M.isRulesSortOn = isOptionOn("rules_sort")
    _M.rulesSortPeriod = _M.get("rules_sort_period") == nil and 60 or tonumber(_M.get("rules_sort_period"))

    _M.rulePath = rulePath

    _M.ipBlackList_subnet, _M.ipBlackList = ipUtils.mergeAndSort(_M.get("ipBlackList"), readFileToTable(rulePath .. "ipBlackList"))
    _M.ipWhiteList = ipUtils.initIpList(_M.get("ipWhiteList"))


    rulesConfig.blackUrl = readRule(rulePath, "blackUrl")
    rulesConfig.args = readRule(rulePath, "args")
    rulesConfig.whiteUrl = readRule(rulePath, "whiteUrl")
    rulesConfig.post = readRule(rulePath, "post")
    rulesConfig.cookie = readRule(rulePath, "cookie")
    rulesConfig.headers = readRule(rulePath, "headers")
    rulesConfig.cc = readRule(rulePath, "cc")
    rulesConfig.acl = readRule(rulePath, "acl")
    rulesConfig.sensitive, rulesConfig.sensitiveWords = readRule(rulePath, "sensitive")
    rulesConfig["user-agent"] = readRule(rulePath, "user-agent")

    rulesConfig.fileExt = { ruleType = "file-ext", rule = "file-ext", action = "REDIRECT" }
    rulesConfig.whiteIp = { ruleType = "whiteip", rule = "whiteip", action = "ALLOW" }
    rulesConfig.blackIp = { ruleType = "blackip", rule = "blackip", action = "DENY" }
    rulesConfig.unsafeMethod = { ruleType = "unsafe-method", rule = "unsafe http method", action = "DENY" }
    rulesConfig.botTrap = { ruleType = "bot-trap", rule = "bot-trap", autoIpBlock = _M.get("bot_trap_ip_block"), ipBlockTimeout = _M.botTrapIpBlockTimeout, action = _M.get("bot_trap_action") }

    local jsonStr = cjson.encode(rulesConfig)
    dict_config:set("rules", jsonStr)

    _M.rules = rulesConfig

    local redirect_html = _M.get("redirect_html")
    if not redirect_html or #redirect_html == 0 then
        redirect_html = _M.ZHONGKUI_PATH .. "/redirect_html"
    end

    _M.html = readFileToString(redirect_html)
    _M.dashboardHtml = readFileToString(_M.ZHONGKUI_PATH .. "/dashboard/dashboard.html")
end

function _M.get(option)
    return config[option]
end

-- 数组字符串转table ["aaa","bbb","ccc"] -> {"aaa","bbb","ccc"}
local function arrayStrToTable(inputStr)
    -- 移除方括号
    local cleanStr = ngxgsub(inputStr, "[\\[\\]]", "") or ""

    -- 分割字符串并构建 Lua 表
    local luaTable = {}
    for item in ngxgmatch(cleanStr, "([^,\"]+)") do
        local value = trim(item[0])
        if value ~= "" then
            insert(luaTable, value)
        end
    end
    return luaTable
end

-- 配置文件读取并进行语法分析
function _M.parseConfigFile(fileName)
    local file = io.open(fileName, "r")
    local configTable = {}

    if file then
        for line in file:lines() do
            -- 忽略空行和注释行
            local from = ngxfind(line, "^\\s*$|^\\s*#", "jo")
            if from then
                goto continue
            end

            -- 解析键值对
            local m, err = ngxmatch(line, "^\\s*([^\\s=]+)\\s?=\\s?(.+)\\s*$", "isjo")

            if m then
                local key = m[1]
                local value = m[2]

                value = trim(value)

                local regex = configRegex[key]

                -- 对每一项配置进行格式校验，校验不通过则直接返回
                if regex and not ngxfind(value, regex, "isjo") then
                    ngx.log(ngx.ERR, "failed to read config file:", key .. ' ' .. value)
                    return
                end

                if ngxfind(value, "^\".*\"$", "sjo") then -- 带引号字符串 "aaa"
                    value = sub(value, 2, -2)
                elseif ngxfind(value, "^\\[.*\\]$", "sjo") then -- 数组 ["aaa","bbb","ccc"]
                    value = arrayStrToTable(value)
                elseif ngxfind(value, "^\\d+$", "sjo") then  -- 数字
                    value = tonumber(value)
                elseif ngxfind(value, "^(?:true|false)$", "isjo") then  -- 布尔值
                    value = value == "true"
                end

                configTable[key] = value

                -- if type(value) == 'table' then
                --     ngx.log(ngx.ERR, key .. '=' .. table.concat(value, ","))
                -- else
                --     ngx.log(ngx.ERR, key .. '=' .. value .. ' ' .. type(value))
                -- end
            else
                ngx.log(ngx.ERR, "failed to read config file:", err)
            end

            ::continue::
        end
        file:close()
    end

    return configTable
end

-- 加载配置文件
function _M.loadConfigFile()
    local fileName = _M.ZHONGKUI_PATH .. "/conf/zhongkui.conf"
    local configTable = _M.parseConfigFile(fileName)
    config = configTable or {}

    initConfig()

    return configTable
end

-- 修改配置文件
function _M.updateConfigFile(fileName, configTable)
    if not configTable or nkeys(configTable) == 0 then
        return
    end

    -- 打开文件并读取内容
    local file = io.open(fileName, "r+")

    if file then
        local content = file:read("*all")
        local newContent = content

        for key, value in pairs(configTable) do
            newContent = ngxsub(newContent, key .. "\\s?=\\s?([\"\\[])?[^\r\n]*?([\"\\]])?\\n", key .. " = $1" .. value .. "$2\n", "jo")
        end

        file:write(newContent)
        file:close()
    end
end

-- 如果配置文件正确，则重载nginx
function _M.reloadConfigFile()
    local fileName = _M.ZHONGKUI_PATH .. "/conf/zhongkui.conf"
    local configTable = _M.parseConfigFile(fileName)
    if configTable and nkeys(configTable) > 0 then
        -- Nginx重新加载配置文件的系统命令
        local command = "sudo nginx -s reload"
        local code = os.execute(command)

        if code == 0 then
            ngx.log(ngx.INFO, "nginx configuration has been successfully reloaded.")
        else
            ngx.log(ngx.ERR, "failed to reload Nginx configuration.")
        end
    else
        ngx.log(ngx.ERR, "failed to reload Nginx configuration:zhongkui config file error.")
    end
end

return _M
