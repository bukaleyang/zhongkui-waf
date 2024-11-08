-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local config = require "config"
local time = require "time"
local cjson = require "cjson.safe"
local stringutf8 = require "stringutf8"
local logger_factory = require "logger_factory"
local sql = require "sql"
local utils = require "utils"
local constants = require "constants"

local pairs = pairs
local upper = string.upper
local format = string.format
local sub = string.sub
local concat = table.concat
local default_if_blank = stringutf8.default_if_blank
local quote_sql_str = ngx.quote_sql_str

local cjson_encode = cjson.encode

local is_site_option_on = config.is_site_option_on
local is_system_option_on = config.is_system_option_on
local get_system_config = config.get_system_config
local write_sql_to_queue = sql.write_sql_to_queue

local LOG_PATH = config.LOG_PATH
local language = get_system_config('geoip').language ~= '' and get_system_config('geoip').language or 'en'

local function write_attack_log()
    local ctx = ngx.ctx
    local rule_table = ctx.rule_table
    local data = ctx.hit_data
    local action = ctx.action
    local rule = rule_table.rule
    local attack_type = rule_table.attackType
    local severity_level = rule_table.severityLevel
    local securityModule = ctx.module_name

    local request_id = ctx.request_id
    local geoip = ctx.geoip
    local realIp = ctx.ip
    local request_body = ctx.request_body
    local response_body = ctx.response_body

    local country = geoip.country
    local province = geoip.province
    local city = geoip.city

    local country_name = country.names[language] or 'unknown'
    local province_name = province.names[language] or 'unknown'
    local city_name = city.names[language] or 'unknown'
    local longitude = geoip.longitude
    local latitude = geoip.latitude
    local method = ngx.req.get_method()
    local url = ngx.var.request_uri
    local ua = ctx.ua
    local host = default_if_blank(ngx.var.server_name, 'unknown')
    local protocol = ngx.var.server_protocol
    local referer = ngx.var.http_referer
    local attackTime = ngx.localtime()

    if is_system_option_on("attackLog") then
        if get_system_config().attackLog.jsonFormat == "on" then
            local log_table = {
                request_id = request_id,
                attack_type = attack_type,
                ip = realIp,
                ip_country = country_name,
                ip_province = province_name,
                ip_city = city_name,
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
            local log_str, err = cjson_encode(log_table)
            if log_str then
                local host_logger = logger_factory.get_logger(LOG_PATH, host, true)
                host_logger:log(log_str .. '\n')
            else
                ngx.log(ngx.ERR, "failed to encode json: ", err)
            end
        else
            local address = country_name .. province_name .. city_name
            address = default_if_blank(address, '-')
            ua = default_if_blank(ua, '-')
            data = default_if_blank(data, '-')

            local log_str = concat({attack_type, realIp, address, "[" .. attackTime .. "]", '"' .. method, host, url, protocol .. '"', data, '"' .. ua .. '"', '"' .. rule .. '"', action},' ')
            local host_logger = logger_factory.get_logger(LOG_PATH, host, true)
            host_logger:log(log_str .. '\n')
        end
    end

    if is_system_option_on("mysql") then
        local sql_str = '(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %.7f, %.7f, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'

        local req_header = ngx.req.raw_header() or ''
        if #req_header > 0 or request_body then
            request_body = quote_sql_str(req_header .. (request_body or ''))
        else
            request_body = 'NULL'
        end

        local headers = ngx.resp.get_headers()
        if headers or response_body then
            local header = ''
            for key, value in pairs(headers) do
                header = header .. key .. ': ' .. value .. '\n'
            end
            if #header > 0 then
                header = header .. '\n'
            end
            response_body = quote_sql_str(header .. (response_body or ''))
        else
            response_body = 'NULL'
        end

        if referer then
            referer = quote_sql_str(referer)
        else
            referer = 'NULL'
        end

        sql_str = format(sql_str, quote_sql_str(request_id), quote_sql_str(realIp),
            quote_sql_str(country.iso_code or ''), quote_sql_str(country.names['zh-CN'] or ''), quote_sql_str(country.names['en'] or ''),
            quote_sql_str(province.iso_code or ''), quote_sql_str(province.names['zh-CN'] or ''), quote_sql_str(province.names['en'] or ''),
            quote_sql_str(city.iso_code or ''), quote_sql_str(city.names['zh-CN'] or ''), quote_sql_str(city.names['en'] or ''),
            longitude, latitude,
            quote_sql_str(method), quote_sql_str(host), quote_sql_str(ua), referer, quote_sql_str(protocol), quote_sql_str(url), request_body,
            quote_sql_str(ngx.status), response_body, quote_sql_str(attackTime), quote_sql_str(attack_type), quote_sql_str(severity_level), quote_sql_str(securityModule), quote_sql_str(sub(rule, 1, 500)), quote_sql_str(action))

        write_sql_to_queue(constants.KEY_ATTACK_LOG, sql_str)
    end
end

local function write_ip_block_log()
    local ctx = ngx.ctx
    local rule_table = ctx.rule_table
    local attack_type = rule_table.attackType
    local ip_block_expire_in_seconds = rule_table.ipBlockExpireInSeconds
    local ip = ctx.ip
    local action = ctx.action
    local host_logger = logger_factory.get_logger(LOG_PATH .. "ipBlock.log", 'ipBlock', false)
    host_logger:log(concat({ngx.localtime(), ip, attack_type, ip_block_expire_in_seconds .. 's'}, ' ') .. "\n")

    if ip_block_expire_in_seconds == 0 then
        local ipBlackLogger = logger_factory.get_logger(config.CONF_PATH .. "ipBlackList", 'ipBlack', false)
        ipBlackLogger:log(ip .. "\n")
    end

    if is_system_option_on("mysql") then
        local request_id = ctx.request_id
        local geoip = ctx.geoip
        local country = geoip.country
        local province = geoip.province
        local city = geoip.city
        local longitude = geoip.longitude
        local latitude = geoip.latitude
        local start_time = ngx.localtime()
        local endTime = 'NULL'
        if ip_block_expire_in_seconds > 0 then
            endTime = 'DATE_ADD(\'' .. start_time .. '\', INTERVAL ' .. ip_block_expire_in_seconds .. ' SECOND)'
        end

        local sql_str = '(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %.7f, %.7f, %s, %s, %u, %s, %s)'

        sql_str = format(sql_str, quote_sql_str(request_id), quote_sql_str(ip),
            quote_sql_str(country.iso_code or ''), quote_sql_str(country.names['zh-CN'] or ''), quote_sql_str(country.names['en'] or ''),
            quote_sql_str(province.iso_code or ''), quote_sql_str(province.names['zh-CN'] or ''), quote_sql_str(province.names['en'] or ''),
            quote_sql_str(city.iso_code or ''), quote_sql_str(city.names['zh-CN'] or ''), quote_sql_str(city.names['en'] or ''),
            longitude, latitude,
            quote_sql_str(attack_type), quote_sql_str(start_time), ip_block_expire_in_seconds, endTime, quote_sql_str(action))

        write_sql_to_queue(constants.KEY_IP_BLOCK_LOG, sql_str)
    end
end

local function get_ttl()
    local ttl = ngx.ctx.ttl
    if not ttl then
        ttl = time.calculate_seconds_to_next_midnight()
        ngx.ctx.ttl = ttl or 60
    end

    return ttl
end

local function count_waf_status()
    local dict = ngx.shared.dict_req_count
    local status = ngx.status

    if status > 399 and status < 500 then
        utils.dict_incr(dict, constants.KEY_HTTP_4XX, get_ttl)
    elseif status > 499 and status < 600 then
        utils.dict_incr(dict, constants.KEY_HTTP_5XX, get_ttl)
    end

    utils.dict_incr(dict, constants.KEY_REQUEST_TIMES, get_ttl)

    local is_attack = ngx.ctx.is_attack
    if is_attack then
        utils.dict_incr(dict, constants.KEY_ATTACK_TIMES, get_ttl)
    end

    if ngx.ctx.blocked then
        utils.dict_incr(dict, constants.KEY_BLOCK_TIMES, get_ttl)
    end
end

local function count_traffic_stats()
    local ctx = ngx.ctx
    local geoip = ctx.geoip
    if geoip then
        local country = geoip.country
        local province = geoip.province
        local city = geoip.city

        local country_code = country.iso_code or ''
        local country_cn = country.names['zh-CN'] or ''
        local country_en = country.names['en'] or ''

        local province_code = province.iso_code or ''
        local province_cn = province.names['zh-CN'] or ''
        local province_en = province.names['en'] or ''

        local city_code = city.iso_code or ''
        local city_cn = city.names['zh-CN'] or ''
        local city_en = city.names['en'] or ''

        local dict = ngx.shared.dict_req_count_citys
        local prefix = country_code .. '_' .. country_cn .. '_' .. country_en .. '_' .. province_code .. '_' .. province_cn .. '_' .. province_en  .. '_'.. city_code .. '_' .. city_cn .. '_' .. city_en .. ':'

        utils.dict_incr(dict, prefix .. constants.KEY_REQUEST_TIMES, get_ttl)

        local is_attack = ctx.is_attack
        if is_attack then
            utils.dict_incr(dict, prefix .. constants.KEY_ATTACK_TIMES, get_ttl)
        end

        if ctx.blocked then
            utils.dict_incr(dict, prefix .. constants.KEY_BLOCK_TIMES, get_ttl)
        end
    end
end

-- 按小时统计当天请求流量，存入缓存，key格式：2023-05-05 09
local function count_request_traffic()
    local hour = time.get_date_hour()
    local dict = ngx.shared.dict_req_count
    utils.dict_incr(dict, hour, get_ttl)
end

--[[
    按小时统计当天攻击请求流量，存入缓存，key格式：attack_2023-05-05 09
    按天统计当天所有攻击类型流量，存入缓存，key格式：attack_type_2023-05-05_ARGS
]]
local function count_attack_request_traffic()
    local rule_table = ngx.ctx.rule_table
    local attack_type = upper(rule_table.attackType)
    local dict = ngx.shared.dict_req_count

    if attack_type ~= 'WHITEIP' then
        local hour = time.get_date_hour()
        utils.dict_incr(dict, constants.KEY_ATTACK_PREFIX .. hour, get_ttl)
    end

    local today = ngx.today() .. '_'

    utils.dict_incr(dict, constants.KEY_ATTACK_TYPE_PREFIX .. today .. attack_type, get_ttl)
end


if is_site_option_on("waf") then
    count_request_traffic()

    count_waf_status()
    count_traffic_stats()

    local is_attack = ngx.ctx.is_attack
    if is_attack then
        write_attack_log()
        count_attack_request_traffic()
    end

    if ngx.ctx.ip_blocked then
        write_ip_block_log()
    end

end
