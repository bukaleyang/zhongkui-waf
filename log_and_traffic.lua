-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local config = require "config"
local time = require "time"
local cjson = require "cjson.safe"
local stringutf8 = require "stringutf8"
local loggerFactory = require "loggerFactory"
local sql = require "sql"
local utils = require "utils"
local constants = require "constants"

local pairs = pairs
local upper = string.upper
local format = string.format
local concat = table.concat
local defaultIfBlank = stringutf8.defaultIfBlank
local quote_sql_str = ngx.quote_sql_str

local logPath = config.logPath
local language = config.get("geoip_language") ~= '' and config.get("geoip_language") or 'en'

local function writeAttackLog()
    local ctx = ngx.ctx
    local ruleTable = ctx.ruleTable
    local data = ctx.hitData
    local action = ctx.action
    local rule = ruleTable.rule
    local ruleType = ruleTable.ruleType

    local requestId = ctx.requestId
    local geoip = ctx.geoip
    local realIp = ctx.ip
    local requestBody = ctx.request_body
    local responseBody = ctx.response_body

    local country = geoip.country
    local province = geoip.province
    local city = geoip.city

    local countryName = country.names[language] or 'unknown'
    local provinceName = province.names[language] or 'unknown'
    local cityName = city.names[language] or 'unknown'
    local longitude = geoip.longitude
    local latitude = geoip.latitude
    local method = ngx.req.get_method()
    local url = ngx.var.request_uri
    local ua = ctx.ua
    local host = defaultIfBlank(ngx.var.server_name, 'unknown')
    local protocol = ngx.var.server_protocol
    local referer = ngx.var.http_referer
    local attackTime = ngx.localtime()

    if config.isAttackLogOn then
        if config.isJsonFormatLogOn then
            local logTable = {
                request_id = requestId,
                attack_type = ruleType,
                ip = realIp,
                ip_country = countryName,
                ip_province = provinceName,
                ip_city = cityName,
                ip_longitude = longitude,
                ip_latitude = latitude,
                attack_time = attackTime,
                http_method = method,
                server = host,
                request_uri = url,
                request_protocol = protocol,
                request_data = data or '',
                user_agent = ua,
                hit_rule = rule,
                action = action
            }
            local logStr, err = cjson.encode(logTable)
            if logStr then
                local hostLogger = loggerFactory.getLogger(logPath, host, true)
                hostLogger:log(logStr .. '\n')
            else
                ngx.log(ngx.ERR, "failed to encode json: ", err)
            end
        else
            local address = countryName .. provinceName .. cityName
            address = defaultIfBlank(address, '-')
            ua = defaultIfBlank(ua, '-')
            data = defaultIfBlank(data, '-')

            local logStr = concat({ruleType, realIp, address, "[" .. attackTime .. "]", '"' .. method, host, url, protocol .. '"', data, '"' .. ua .. '"', '"' .. rule .. '"', action},' ')
            local hostLogger = loggerFactory.getLogger(logPath, host, true)
            hostLogger:log(logStr .. '\n')
        end
    end

    if config.isMysqlOn then
        local sqlStr = '(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %.7f, %.7f, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'

        local reqHeader = ngx.req.raw_header() or ''
        if #reqHeader > 0 or requestBody then
            requestBody = quote_sql_str(reqHeader .. (requestBody or ''))
        else
            requestBody = 'NULL'
        end

        local headers = ngx.resp.get_headers()
        if headers or responseBody then
            local header = ''
            for key, value in pairs(headers) do
                header = header .. key .. ': ' .. value .. '\n'
            end
            if #header > 0 then
                header = header .. '\n'
            end
            responseBody = quote_sql_str(header .. (responseBody or ''))
        else
            responseBody = 'NULL'
        end

        if referer then
            referer = quote_sql_str(referer)
        else
            referer = 'NULL'
        end

        sqlStr = format(sqlStr, quote_sql_str(requestId), quote_sql_str(realIp),
            quote_sql_str(country.iso_code or ''), quote_sql_str(country.names['zh-CN'] or ''), quote_sql_str(country.names['en'] or ''),
            quote_sql_str(province.iso_code or ''), quote_sql_str(province.names['zh-CN'] or ''), quote_sql_str(province.names['en'] or ''),
            quote_sql_str(city.iso_code or ''), quote_sql_str(city.names['zh-CN'] or ''), quote_sql_str(city.names['en'] or ''),
            longitude, latitude,
            quote_sql_str(method), quote_sql_str(host), quote_sql_str(ua), referer, quote_sql_str(protocol), quote_sql_str(url), requestBody,
            quote_sql_str(ngx.status), responseBody, quote_sql_str(attackTime), quote_sql_str(ruleType), quote_sql_str(rule), quote_sql_str(action))

        sql.writeSqlToQueue(constants.KEY_ATTACK_LOG, sqlStr)
    end
end

local function writeIPBlockLog()
    local ctx = ngx.ctx
    local ruleTable = ctx.ruleTable
    local ruleType = ruleTable.ruleType
    local ipBlockTimeout = ruleTable.ipBlockTimeout
    local ip = ctx.ip
    local action = ctx.action
    local hostLogger = loggerFactory.getLogger(logPath .. "ipBlock.log", 'ipBlock', false)
    hostLogger:log(concat({ngx.localtime(), ip, ruleType, ipBlockTimeout .. 's'}, ' ') .. "\n")

    if ipBlockTimeout == 0 then
        local ipBlackLogger = loggerFactory.getLogger(config.rulePath .. "ipBlackList", 'ipBlack', false)
        ipBlackLogger:log(ip .. "\n")
    end

    if config.isMysqlOn then
        local requestId = ctx.requestId
        local geoip = ctx.geoip
        local country = geoip.country
        local province = geoip.province
        local city = geoip.city
        local longitude = geoip.longitude
        local latitude = geoip.latitude
        local startTime = ngx.localtime()
        local endTime = 'NULL'
        if ipBlockTimeout > 0 then
            endTime = 'DATE_ADD(\'' .. startTime .. '\', INTERVAL ' .. ipBlockTimeout .. ' SECOND)'
        end

        local sqlStr = '(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %.7f, %.7f, %s, %s, %u, %s, %s)'

        sqlStr = format(sqlStr, quote_sql_str(requestId), quote_sql_str(ip),
            quote_sql_str(country.iso_code or ''), quote_sql_str(country.names['zh-CN'] or ''), quote_sql_str(country.names['en'] or ''),
            quote_sql_str(province.iso_code or ''), quote_sql_str(province.names['zh-CN'] or ''), quote_sql_str(province.names['en'] or ''),
            quote_sql_str(city.iso_code or ''), quote_sql_str(city.names['zh-CN'] or ''), quote_sql_str(city.names['en'] or ''),
            longitude, latitude,
            quote_sql_str(ruleType), quote_sql_str(startTime), ipBlockTimeout, endTime, quote_sql_str(action))

        sql.writeSqlToQueue(constants.KEY_IP_BLOCK_LOG, sqlStr)
    end
end

local function getTTL()
    local ttl = ngx.ctx.ttl
    if not ttl then
        ttl = time.calculateSecondsToNextMidnight()
        ngx.ctx.ttl = ttl or 60
    end

    return ttl
end

local function countWafStatus()
    local status = ngx.status

    local dict = ngx.shared.dict_req_count

    if status > 399 and status < 500 then
        utils.dictIncr(dict, constants.KEY_HTTP_4XX, getTTL)
    elseif status > 499 and status < 600 then
        utils.dictIncr(dict, constants.KEY_HTTP_5XX, getTTL)
    end

    utils.dictIncr(dict, constants.KEY_REQUEST_TIMES, getTTL)

    local isAttack = ngx.ctx.isAttack
    if isAttack then
        utils.dictIncr(dict, constants.KEY_ATTACK_TIMES, getTTL)
    end

    if ngx.ctx.blocked then
        utils.dictIncr(dict, constants.KEY_BLOCK_TIMES, getTTL)
    end
end

local function countTrafficStats()
    local ctx = ngx.ctx
    local geoip = ctx.geoip
    if geoip then
        local country = geoip.country
        local province = geoip.province
        local city = geoip.city

        local countryCode = country.iso_code or ''
        local countryCN = country.names['zh-CN'] or ''
        local countryEN = country.names['en'] or ''

        local provinceCode = province.iso_code or ''
        local provinceCN = province.names['zh-CN'] or ''
        local provinceEN = province.names['en'] or ''

        local cityCode = city.iso_code or ''
        local cityCN = city.names['zh-CN'] or ''
        local cityEN = city.names['en'] or ''

        local dict = ngx.shared.dict_req_count_citys
        local prefix = countryCode .. '_' .. countryCN .. '_' .. countryEN .. '_' .. provinceCode .. '_' .. provinceCN .. '_' .. provinceEN  .. '_'.. cityCode .. '_' .. cityCN .. '_' .. cityEN .. ':'

        utils.dictIncr(dict, prefix .. constants.KEY_REQUEST_TIMES, getTTL)

        local isAttack = ctx.isAttack
        if isAttack then
            utils.dictIncr(dict, prefix .. constants.KEY_ATTACK_TIMES, getTTL)
        end

        if ctx.blocked then
            utils.dictIncr(dict, prefix .. constants.KEY_BLOCK_TIMES, getTTL)
        end
    end
end

-- 按小时统计当天请求流量，存入缓存，key格式：2023-05-05 09
local function countRequestTraffic()
    local hour = time.getDateHour()
    local dict = ngx.shared.dict_req_count
    utils.dictIncr(dict, hour, getTTL)
end

--[[
    按小时统计当天攻击请求流量，存入缓存，key格式：attack_2023-05-05 09
    按天统计当天所有攻击类型流量，存入缓存，key格式：attack_type_2023-05-05_ARGS
]]
local function countAttackRequestTraffic()
    local ruleTable = ngx.ctx.ruleTable
    local ruleType = upper(ruleTable.ruleType)
    local dict = ngx.shared.dict_req_count

    if ruleType ~= 'WHITEIP' then
        local hour = time.getDateHour()
        utils.dictIncr(dict, constants.KEY_ATTACK_PREFIX .. hour, getTTL)
    end

    local today = ngx.today() .. '_'

    utils.dictIncr(dict, constants.KEY_ATTACK_TYPE_PREFIX .. today .. ruleType, getTTL)
end


if config.isWAFOn then
    countRequestTraffic()

    countWafStatus()
    countTrafficStats()

    local isAttack = ngx.ctx.isAttack
    if isAttack then
        writeAttackLog()
        countAttackRequestTraffic()
    end

    if ngx.ctx.ipBlocked then
        writeIPBlockLog()
    end

end
