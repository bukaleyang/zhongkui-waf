-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

local mysql = require "mysqlCli"
local config = require "config"
local utils = require "utils"
local constants = require "constants"

local ipairs = ipairs
local pairs = pairs
local newtab = table.new
local concat = table.concat
local insert = table.insert
local ngxmatch = ngx.re.match
local floor = math.floor
local format = string.format
local quote_sql_str = ngx.quote_sql_str

local _M = {}

local database = config.get("mysql_database")
local KEY_ATTACK_LOG = 'attack_log'

local BATCH_SIZE = 300

local SQL_CHECK_TABLE = [[SELECT COUNT(*) AS c FROM INFORMATION_SCHEMA.TABLES WHERE table_schema='%s' AND table_name='%s']]

local SQL_CREATE_TABLE_WAF_STATUS = [[
    CREATE TABLE `waf_status` (
        `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        `http4xx` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'http状态码4xx数',
        `http5xx` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'http状态码5xx数',
        `request_times` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '请求数',
        `attack_times` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '攻击请求数',
        `block_times` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '拦截数',
        `request_date` CHAR(10) NOT NULL COMMENT '日期',

        `update_time` datetime NULL,
        `create_time` datetime DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;
    CREATE UNIQUE INDEX idx_unique_waf_status_request_date ON waf_status (request_date);
]]

local SQL_INSERT_WAF_STATUS = [[
    INSERT INTO waf_status (http4xx, http5xx, request_times, attack_times, block_times, request_date) 
    VALUES(%u, %u, %u, %u, %u, %s) ON DUPLICATE KEY UPDATE http4xx = http4xx + VALUES(http4xx),
    http5xx = http5xx + VALUES(http5xx),request_times = request_times + VALUES(request_times),
    attack_times = attack_times + VALUES(attack_times),block_times = block_times + VALUES(block_times), update_time = NOW();
]]

local SQL_GET_TODAY_WAF_STATUS = [[SELECT * FROM waf_status WHERE DATE(request_date) = CURDATE() ORDER BY id DESC LIMIT 1;]]

local SQL_CREATE_TABLE_TRAFFIC_STATS = [[
    CREATE TABLE `traffic_stats` (
        `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

        `ip_country_code` CHAR(2) NULL COMMENT 'ip所属国家代码',
        `ip_country_cn` VARCHAR(255) NULL COMMENT 'ip所属国家_中文',
        `ip_country_en` VARCHAR(255) NULL COMMENT 'ip所属国家_英文',
        `ip_province_code` VARCHAR(50) NULL COMMENT 'ip所属省份代码',
        `ip_province_cn` VARCHAR(255) NULL COMMENT 'ip所属省份_中文',
        `ip_province_en` VARCHAR(255) NULL COMMENT 'ip所属省份_英文',
        `ip_city_code` VARCHAR(50) NULL COMMENT 'ip所属城市代码',
        `ip_city_cn` VARCHAR(255) NULL COMMENT 'ip所属城市_中文',
        `ip_city_en` VARCHAR(255) NULL COMMENT 'ip所属城市_英文',

        `request_times` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '请求数',
        `attack_times` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '攻击请求数',
        `block_times` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '拦截数',
        `request_date` CHAR(10) NOT NULL COMMENT '日期',

        `update_time` datetime NULL,
        `create_time` datetime DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
    CREATE UNIQUE INDEX idx_unique_traffic_stats_request_date ON traffic_stats (ip_country_code, ip_province_en, ip_city_en, request_date);
]]

local SQL_INSERT_TRAFFIC_STATS = [[
    INSERT INTO traffic_stats (ip_country_code, ip_country_cn, ip_country_en, ip_province_code, ip_province_cn, ip_province_en, ip_city_code, ip_city_cn, ip_city_en, request_times, attack_times, block_times, request_date) 
    VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %u, %u, %u, %s) ON DUPLICATE KEY UPDATE request_times = request_times + VALUES(request_times),
    attack_times = attack_times + VALUES(attack_times),block_times = block_times + VALUES(block_times), update_time = NOW();
]]

local SQL_GET_30DAYS_WORLD_TRAFFIC_STATS = [[SELECT ip_country_code AS 'iso_code',ip_country_cn AS 'name_cn', ip_country_en AS 'name_en',
            SUM(request_times) AS request_times,SUM(attack_times) AS attack_times,SUM(block_times) AS block_times
            FROM traffic_stats WHERE DATE(request_date) >= CURDATE() - INTERVAL 30 DAY GROUP BY ip_country_code, ip_country_cn, ip_country_en;]]

local SQL_GET_30DAYS_CHINA_TRAFFIC_STATS = [[SELECT ip_province_code AS 'iso_code',ip_province_cn AS 'name_cn', ip_province_en AS 'name_en',
            SUM(request_times) AS request_times,SUM(attack_times) AS attack_times,SUM(block_times) AS block_times
            FROM traffic_stats WHERE ip_country_code='CN' AND DATE(request_date) >= CURDATE() - INTERVAL 30 DAY GROUP BY ip_province_code, ip_province_cn, ip_province_en;]]

local SQL_CREATE_TABLE_ATTACK_LOG = [[
    CREATE TABLE `attack_log` (
        `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        `request_id` CHAR(20) NOT NULL COMMENT '请求id',
      
        `ip` varchar(32) NOT NULL COMMENT 'ip地址',
        `ip_country_code` CHAR(2) NULL COMMENT 'ip所属国家代码',
        `ip_country_cn` VARCHAR(255) NULL COMMENT 'ip所属国家_中文',
        `ip_country_en` VARCHAR(255) NULL COMMENT 'ip所属国家_英文',
        `ip_province_code` VARCHAR(50) NULL COMMENT 'ip所属省份代码',
        `ip_province_cn` VARCHAR(255) NULL COMMENT 'ip所属省份_中文',
        `ip_province_en` VARCHAR(255) NULL COMMENT 'ip所属省份_英文',
        `ip_city_code` VARCHAR(50) NULL COMMENT 'ip所属城市代码',
        `ip_city_cn` VARCHAR(255) NULL COMMENT 'ip所属城市_中文',
        `ip_city_en` VARCHAR(255) NULL COMMENT 'ip所属城市_英文',
        `ip_longitude` DECIMAL(10, 7) NULL COMMENT 'ip地理位置经度',
        `ip_latitude` DECIMAL(10, 7) NULL COMMENT 'ip地理位置纬度',
          
        `http_method` VARCHAR(20) NULL COMMENT '请求http方法',
        `server_name` VARCHAR(100) NULL COMMENT '请求域名',
        `user_agent` VARCHAR(200) NULL COMMENT '请求客户端ua',
        `referer` VARCHAR(500) NULL COMMENT 'referer',
    
        `request_protocol` VARCHAR(50) NULL COMMENT '请求协议',
        `request_uri` VARCHAR(100) NULL COMMENT '请求uri',
        `request_body` MEDIUMTEXT NULL COMMENT '请求体',
        `http_status` SMALLINT UNSIGNED NOT NULL COMMENT 'http响应状态码',
        `response_body` MEDIUMTEXT NULL COMMENT '响应体',
        `request_time` datetime NOT NULL,
          
        `attack_type` VARCHAR(200) NULL COMMENT '攻击类型',
        `hit_rule` VARCHAR(200) NULL COMMENT '命中规则',
        `action` VARCHAR(100) NULL COMMENT '处置动作',
        
        `update_time` datetime NULL,
        `create_time` datetime DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (`id`)
      ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;
]]

local SQL_INSERT_ATTACK_LOG = [[
    INSERT INTO attack_log (
        request_id, ip, ip_country_code, ip_country_cn, ip_country_en, ip_province_code, ip_province_cn, ip_province_en, ip_city_code, ip_city_cn, ip_city_en,
        ip_longitude, ip_latitude, http_method, server_name, user_agent, referer, request_protocol, request_uri,  
        request_body, http_status, response_body, request_time, attack_type, hit_rule, action) 
    VALUES
]]


function _M.checkTable(premature)
    if premature then
        return
    end

    local res, err = mysql.query(format(SQL_CHECK_TABLE, database, 'waf_status'))
    if res and res[1] and res[1].c == '0' then
        res, err = mysql.query(SQL_CREATE_TABLE_WAF_STATUS)
        if not res then
            ngx.log(ngx.ERR, 'failed to create table waf_status ', err)
        end
    end

    res = mysql.query(format(SQL_CHECK_TABLE, database, 'traffic_stats'))
    if res and res[1] and res[1].c == '0' then
        res, err = mysql.query(SQL_CREATE_TABLE_TRAFFIC_STATS)
        if not res then
            ngx.log(ngx.ERR, 'failed to create table traffic_stats ', err)
        end
    end

    res = mysql.query(format(SQL_CHECK_TABLE, database, 'attack_log'))

    if res and res[1] and res[1].c == '0' then
        res, err = mysql.query(SQL_CREATE_TABLE_ATTACK_LOG)
        if not res then
            ngx.log(ngx.ERR, 'failed to create table attack_log ', err)
        end
    end
end

local function flushUnlock()
    local dict_lock = ngx.shared.dict_locks
    local succ, err = dict_lock:set(KEY_ATTACK_LOG, false)
    if not succ then
        ngx.log(ngx.ERR, "failed to unlock " .. KEY_ATTACK_LOG .. ": ", err)
    end

    return succ
end

function _M.updateTrafficStats()
    local dict = ngx.shared.dict_req_count_citys
    local keys = dict:get_keys()

    if keys then
        local keyTable = {}

        for _, key in ipairs(keys) do
            local m, err = ngxmatch(key, '(.*?)_(.*?)_(.*?)_(.*?)_(.*?)_(.*?)_(.*?)_(.*?)_(.*?):', 'isjo')
            if m then
                local prefix = m[0]

                local countryCode = m[1] or ''
                local countryCN = m[2] or ''
                local countryEN = m[3] or ''

                local provinceCode = m[4] or ''
                local provinceCN = m[5] or ''
                local provinceEN = m[6] or ''

                local cityCode = m[7] or ''
                local cityCN = m[8] or ''
                local cityEN = m[9] or ''

                insert(keyTable, {prefix = prefix,
                                countryCode = countryCode, countryCN = countryCN, countryEN = countryEN,
                                provinceCode = provinceCode, provinceCN = provinceCN, provinceEN = provinceEN,
                                cityCode = cityCode, cityCN = cityCN, cityEN = cityEN})
            end
        end

        for _, t in pairs(keyTable) do
            local prefix = t.prefix

            local request_times = utils.dictGet(dict, prefix .. constants.KEY_REQUEST_TIMES) or 0
            local attack_times = utils.dictGet(dict, prefix .. constants.KEY_ATTACK_TIMES) or 0
            local block_times = utils.dictGet(dict, prefix .. constants.KEY_BLOCK_TIMES) or 0

            if request_times > 0 or attack_times > 0 or block_times > 0 then
                utils.dictSet(dict, prefix .. constants.KEY_REQUEST_TIMES, 0, constants.TTL_KEY_COUNT_CITYS)
                utils.dictSet(dict, prefix .. constants.KEY_ATTACK_TIMES, 0, constants.TTL_KEY_COUNT_CITYS)
                utils.dictSet(dict, prefix .. constants.KEY_BLOCK_TIMES, 0, constants.TTL_KEY_COUNT_CITYS)

                local sql = format(SQL_INSERT_TRAFFIC_STATS,
                            quote_sql_str(t.countryCode), quote_sql_str(t.countryCN), quote_sql_str(t.countryEN),
                            quote_sql_str(t.provinceCode), quote_sql_str(t.provinceCN), quote_sql_str(t.provinceEN),
                            quote_sql_str(t.cityCode), quote_sql_str(t.cityCN), quote_sql_str(t.cityEN),
                            request_times, attack_times, block_times, quote_sql_str(ngx.today()))

                mysql.query(sql)
            end
        end
    end
end

function _M.updateWafStatus()
    local dict = ngx.shared.dict_req_count

    local http4xx = utils.dictGet(dict, constants.KEY_HTTP_4XX) or 0
    local http5xx = utils.dictGet(dict, constants.KEY_HTTP_5XX) or 0
    local request_times = utils.dictGet(dict, constants.KEY_REQUEST_TIMES) or 0
    local attack_times = utils.dictGet(dict, constants.KEY_ATTACK_TIMES) or 0
    local block_times = utils.dictGet(dict, constants.KEY_BLOCK_TIMES) or 0

    if http4xx == 0 and http5xx == 0 and request_times == 0 and attack_times == 0 and block_times == 0 then
        return
    end

    utils.dictSet(dict, constants.KEY_HTTP_4XX, 0)
    utils.dictSet(dict, constants.KEY_HTTP_5XX, 0)
    utils.dictSet(dict, constants.KEY_REQUEST_TIMES, 0)
    utils.dictSet(dict, constants.KEY_ATTACK_TIMES, 0)
    utils.dictSet(dict, constants.KEY_BLOCK_TIMES, 0)

    local sql = format(SQL_INSERT_WAF_STATUS, http4xx, http5xx, request_times, attack_times, block_times, quote_sql_str(ngx.today()))

    mysql.query(sql)
end

function _M.getTodayWafStatus()
    return mysql.query(SQL_GET_TODAY_WAF_STATUS)
end

function _M.get30DaysWorldTrafficStats()
    return mysql.query(SQL_GET_30DAYS_WORLD_TRAFFIC_STATS)
end

function _M.get30DaysChinaTrafficStats()
    return mysql.query(SQL_GET_30DAYS_CHINA_TRAFFIC_STATS)
end

function _M.writeAttackLogToMysql(premature)
    if premature then
        return
    end

    local dict_sql_queue = ngx.shared.dict_sql_queue

    local len = dict_sql_queue:llen(KEY_ATTACK_LOG) or 0
    if len == 0 then
        return
    end

    local insertTimeTotal = floor(len / BATCH_SIZE) + 1
    local insertTime = 0

    local buffer = newtab(BATCH_SIZE, 0)

    local index = 1
    local value = dict_sql_queue:lpop(KEY_ATTACK_LOG)

    while (insertTime <= insertTimeTotal and value) do
        buffer[index] = value
        value = dict_sql_queue:lpop(KEY_ATTACK_LOG)

        if index == BATCH_SIZE or value == nil then
            local sql_values = concat(buffer, ',')

            if sql_values then
                mysql.query(SQL_INSERT_ATTACK_LOG .. sql_values)
                insertTime = insertTime + 1
            end

            index = 1
            buffer = newtab(BATCH_SIZE, 0)
        else
            index = index + 1
        end
    end

    flushUnlock()
end


function _M.writeAttackLogToQueue(sql)
    local dict_sql_queue = ngx.shared.dict_sql_queue

    dict_sql_queue:rpush(KEY_ATTACK_LOG, sql)
end


return _M
