-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

local mysql = require "mysql_cli"
local config = require "config"
local utils = require "utils"
local constants = require "constants"

local ipairs = ipairs
local pairs = pairs
local newtab = table.new
local concat = table.concat
local insert = table.insert
local ngxmatch = ngx.re.match
local quote_sql_str = ngx.quote_sql_str
local format = string.format
local gsub = string.gsub
local floor = math.floor
local tonumber = tonumber
local get_system_config = config.get_system_config

local _M = {}

local database = get_system_config('mysql').database

local BATCH_SIZE = 300
-- 按字节二次切批，避免大 body 让单条 INSERT 超过 mysql_cli 的 max_packet_size
local BATCH_MAX_BYTES = 4 * 1024 * 1024

-- 攻击日志保留期清理：每次删除的行数，避免单个大事务长时间锁行
local PURGE_BATCH_SIZE = 2000
-- 单次运行最多删除的批数，避免首次清理存量时长时间占用数据库
local PURGE_MAX_BATCHES = 1000
local PURGE_DEFAULT_DAYS = 180

local SQL_CHECK_TABLE = [[SELECT COUNT(*) AS c FROM INFORMATION_SCHEMA.TABLES WHERE table_schema='%s' AND table_name='%s']]
local SQL_CHECK_INDEX = [[SELECT COUNT(*) AS c FROM INFORMATION_SCHEMA.STATISTICS WHERE table_schema=DATABASE() AND table_name='%s' AND index_name='%s']]
local SQL_DELETE_EXPIRED_ATTACK_LOG = 'DELETE FROM attack_log WHERE request_time < DATE_SUB(NOW(), INTERVAL %d DAY) ORDER BY request_time LIMIT %d'

local SQL_CREATE_TABLE_WAF_STATUS = [[
    CREATE TABLE `waf_status` (
        `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        `site_id` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '站点id，0表示全部站点',
        `server_name` VARCHAR(100) NOT NULL DEFAULT '' COMMENT '站点主域名，冗余保存便于站点删除后识别',
        `http4xx` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'http状态码4xx数',
        `http5xx` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'http状态码5xx数',
        `request_times` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '请求数',
        `attack_times` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '攻击请求数',
        `block_times` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '总拦截数',
        `block_times_attack` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '攻击拦截数',
        `block_times_captcha` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '触发人机验证数',
        `block_times_cc` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'cc拦截数',
        `captcha_pass_times` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '人机验证通过数',
        `request_date` DATE NOT NULL COMMENT '日期',
        `update_time` datetime NULL,
        `create_time` datetime DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;
]]

local SQL_INSERT_WAF_STATUS_HEAD = [[
    INSERT INTO waf_status (site_id, server_name, http4xx, http5xx, request_times, attack_times, block_times, block_times_attack, block_times_captcha, block_times_cc, captcha_pass_times, request_date)
    VALUES
]]

local SQL_INSERT_WAF_STATUS_TAIL = [[
    ON DUPLICATE KEY UPDATE http4xx = http4xx + VALUES(http4xx),
    http5xx = http5xx + VALUES(http5xx),request_times = request_times + VALUES(request_times),
    attack_times = attack_times + VALUES(attack_times),block_times = block_times + VALUES(block_times),
    block_times_attack = block_times_attack + VALUES(block_times_attack),
    block_times_captcha = block_times_captcha + VALUES(block_times_captcha),
    block_times_cc = block_times_cc + VALUES(block_times_cc),
    captcha_pass_times = captcha_pass_times + VALUES(captcha_pass_times),
    update_time = NOW();
]]

-- site_id, server_name, 4xx, 5xx, 请求数, 攻击数, 总拦截, 攻击拦截, 人机验证, cc拦截, 验证通过, 日期
local WAF_STATUS_ROW_FORMAT = '(%u, %s, %u, %u, %u, %u, %u, %u, %u, %u, %u, %s)'

-- request_date 是 DATE，直接用 CURDATE() 比较，可命中 idx_unique_waf_status_date_site
local SQL_GET_TODAY_WAF_STATUS = [[SELECT * FROM waf_status WHERE request_date = CURDATE() AND site_id = @SITE_ID@ ORDER BY id DESC LIMIT 1;]]

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
        `block_times_attack` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '攻击拦截数',
        `block_times_captcha` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '触发人机验证数',
        `block_times_cc` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'cc拦截数',
        `captcha_pass_times` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '人机验证通过数',

        `request_date` DATE NOT NULL COMMENT '日期',

        `update_time` datetime NULL,
        `create_time` datetime DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
]]

local SQL_CREATE_TABLE_TRAFFIC_STATS_COUNTRY_DAILY = [[
    CREATE TABLE `traffic_stats_country_daily` (
        `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        `request_date` DATE NOT NULL COMMENT '日期',
        `site_id` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '站点id，0表示全部站点',
        `server_name` VARCHAR(100) NOT NULL DEFAULT '' COMMENT '站点主域名，冗余保存便于站点删除后识别',
        `ip_country_code` CHAR(2) NOT NULL DEFAULT '' COMMENT '国家代码',
        `ip_country_cn` VARCHAR(255) NOT NULL DEFAULT '' COMMENT '国家_中文',
        `ip_country_en` VARCHAR(255) NOT NULL DEFAULT '' COMMENT '国家_英文',
        `request_times` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '请求数',
        `attack_times` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '攻击请求数',
        `block_times` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '拦截数',
        `block_times_attack` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '攻击拦截数',
        `block_times_captcha` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '触发人机验证数',
        `block_times_cc` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'cc拦截数',
        `captcha_pass_times` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '人机验证通过数',
        `update_time` datetime NULL,
        `create_time` datetime DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (`id`),
        UNIQUE KEY `idx_unique_traffic_stats_country_daily` (`request_date`, `site_id`, `ip_country_code`, `ip_country_en`)
    ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
]]

local SQL_CREATE_TABLE_TRAFFIC_STATS_PROVINCE_DAILY = [[
    CREATE TABLE `traffic_stats_province_daily` (
        `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        `request_date` DATE NOT NULL COMMENT '日期',
        `site_id` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '站点id，0表示全部站点',
        `server_name` VARCHAR(100) NOT NULL DEFAULT '' COMMENT '站点主域名，冗余保存便于站点删除后识别',
        `ip_country_code` CHAR(2) NOT NULL DEFAULT '' COMMENT '国家代码',
        `ip_province_code` VARCHAR(50) NOT NULL DEFAULT '' COMMENT '省份代码',
        `ip_province_cn` VARCHAR(255) NOT NULL DEFAULT '' COMMENT '省份_中文',
        `ip_province_en` VARCHAR(255) NOT NULL DEFAULT '' COMMENT '省份_英文',
        `request_times` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '请求数',
        `attack_times` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '攻击请求数',
        `block_times` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '拦截数',
        `block_times_attack` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '攻击拦截数',
        `block_times_captcha` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '触发人机验证数',
        `block_times_cc` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'cc拦截数',
        `captcha_pass_times` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '人机验证通过数',
        `update_time` datetime NULL,
        `create_time` datetime DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (`id`),
        UNIQUE KEY `idx_unique_traffic_stats_province_daily` (`request_date`, `site_id`, `ip_country_code`, `ip_province_code`, `ip_province_en`)
    ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
]]

-- 批量 upsert，避免逐城市单条 SQL 造成连接池/唯一索引写放大
local SQL_INSERT_TRAFFIC_STATS_HEAD = [[
    INSERT INTO traffic_stats (ip_country_code, ip_country_cn, ip_country_en, ip_province_code, ip_province_cn, ip_province_en, ip_city_code, ip_city_cn, ip_city_en, request_times, attack_times, block_times,
    block_times_attack, block_times_captcha, block_times_cc, captcha_pass_times, request_date)
    VALUES
]]

local SQL_INSERT_TRAFFIC_STATS_TAIL = [[
    ON DUPLICATE KEY UPDATE request_times = request_times + VALUES(request_times),
    attack_times = attack_times + VALUES(attack_times),block_times = block_times + VALUES(block_times),
    block_times_attack = block_times_attack + VALUES(block_times_attack),
    block_times_captcha = block_times_captcha + VALUES(block_times_captcha),
    block_times_cc = block_times_cc + VALUES(block_times_cc),
    captcha_pass_times = captcha_pass_times + VALUES(captcha_pass_times),
    update_time = NOW();
]]

local SQL_INSERT_TRAFFIC_STATS_COUNTRY_HEAD = [[
    INSERT INTO traffic_stats_country_daily (request_date, site_id, server_name, ip_country_code, ip_country_cn, ip_country_en, request_times, attack_times, block_times,
    block_times_attack, block_times_captcha, block_times_cc, captcha_pass_times)
    VALUES
]]

local SQL_INSERT_TRAFFIC_STATS_COUNTRY_TAIL = [[
    ON DUPLICATE KEY UPDATE request_times = request_times + VALUES(request_times),
    attack_times = attack_times + VALUES(attack_times),
    block_times = block_times + VALUES(block_times),
    block_times_attack = block_times_attack + VALUES(block_times_attack),
    block_times_captcha = block_times_captcha + VALUES(block_times_captcha),
    block_times_cc = block_times_cc + VALUES(block_times_cc),
    captcha_pass_times = captcha_pass_times + VALUES(captcha_pass_times),
    update_time = NOW();
]]

local SQL_INSERT_TRAFFIC_STATS_PROVINCE_HEAD = [[
    INSERT INTO traffic_stats_province_daily (request_date, site_id, server_name, ip_country_code, ip_province_code, ip_province_cn, ip_province_en, request_times, attack_times, block_times,
    block_times_attack, block_times_captcha, block_times_cc, captcha_pass_times)
    VALUES
]]

local SQL_INSERT_TRAFFIC_STATS_PROVINCE_TAIL = [[
    ON DUPLICATE KEY UPDATE request_times = request_times + VALUES(request_times),
    attack_times = attack_times + VALUES(attack_times),
    block_times = block_times + VALUES(block_times),
    block_times_attack = block_times_attack + VALUES(block_times_attack),
    block_times_captcha = block_times_captcha + VALUES(block_times_captcha),
    block_times_cc = block_times_cc + VALUES(block_times_cc),
    captcha_pass_times = captcha_pass_times + VALUES(captcha_pass_times),
    update_time = NOW();
]]

-- 按日期范围统计卡片；@DAYS@ 为向前偏移天数（今天=0，近7天=6，近30天=29）
local SQL_GET_RANGE_WAF_STATUS = [[
    SELECT COALESCE(SUM(http4xx), 0) AS http4xx,
        COALESCE(SUM(http5xx), 0) AS http5xx,
        COALESCE(SUM(request_times), 0) AS request_times,
        COALESCE(SUM(attack_times), 0) AS attack_times,
        COALESCE(SUM(block_times), 0) AS block_times,
        COALESCE(SUM(block_times_attack), 0) AS block_times_attack,
        COALESCE(SUM(block_times_captcha), 0) AS block_times_captcha,
        COALESCE(SUM(block_times_cc), 0) AS block_times_cc,
        COALESCE(SUM(captcha_pass_times), 0) AS captcha_pass_times
    FROM waf_status
    WHERE site_id = @SITE_ID@
      AND request_date >= CURDATE() - INTERVAL @DAYS@ DAY
      AND request_date <= CURDATE();
]]

-- 按天返回流量曲线；近7天/近30天使用，今天仍走共享字典的小时数据
local SQL_GET_RANGE_TRAFFIC_STATS = [[
    SELECT DATE_FORMAT(request_date, '%Y-%m-%d') AS label,
        SUM(request_times) AS request_times,
        SUM(attack_times) AS attack_times,
        SUM(block_times) AS block_times
    FROM waf_status
    WHERE site_id = @SITE_ID@
      AND request_date >= CURDATE() - INTERVAL @DAYS@ DAY
      AND request_date <= CURDATE()
    GROUP BY request_date
    ORDER BY request_date;
]]

local SQL_GET_RANGE_WORLD_TRAFFIC_STATS = [[
    SELECT ip_country_code AS 'iso_code', MAX(ip_country_cn) AS 'name_cn', ip_country_en AS 'name_en',
        SUM(request_times) AS request_times,SUM(attack_times) AS attack_times,SUM(block_times) AS block_times,
        SUM(block_times_attack) AS block_times_attack, SUM(block_times_captcha) AS block_times_captcha, SUM(block_times_cc) AS block_times_cc, SUM(captcha_pass_times) AS captcha_pass_times
    FROM traffic_stats_country_daily
    WHERE site_id = @SITE_ID@
      AND request_date >= CURDATE() - INTERVAL @DAYS@ DAY
      AND request_date <= CURDATE()
    -- 唯一键是 code + en；中文名只用于展示，用 MAX 取非空值，避免某天中文名为空时同一国家拆成两行。
    GROUP BY ip_country_code, ip_country_en;
]]

-- 中国地图按省级汇总：包含港澳台，并把 GeoIP 返回的“北京市/河北省”等后缀去掉，
-- 保证 name_cn 与 echarts china.json 的区域名一致；同一区域的多条记录合并为一行。
local SQL_GET_RANGE_CHINA_TRAFFIC_STATS = [[
    SELECT MAX(ip_province_code) AS 'iso_code',
        CASE
            WHEN ip_province_cn LIKE '%特别行政区' THEN LEFT(ip_province_cn, CHAR_LENGTH(ip_province_cn) - 5)
            WHEN ip_province_cn LIKE '%壮族自治区' THEN LEFT(ip_province_cn, CHAR_LENGTH(ip_province_cn) - 5)
            WHEN ip_province_cn LIKE '%回族自治区' THEN LEFT(ip_province_cn, CHAR_LENGTH(ip_province_cn) - 5)
            WHEN ip_province_cn LIKE '%维吾尔自治区' THEN LEFT(ip_province_cn, CHAR_LENGTH(ip_province_cn) - 5)
            WHEN ip_province_cn LIKE '%自治区' THEN LEFT(ip_province_cn, CHAR_LENGTH(ip_province_cn) - 3)
            WHEN ip_province_cn LIKE '%省' THEN LEFT(ip_province_cn, CHAR_LENGTH(ip_province_cn) - 1)
            WHEN ip_province_cn LIKE '%市' THEN LEFT(ip_province_cn, CHAR_LENGTH(ip_province_cn) - 1)
            ELSE ip_province_cn
        END AS 'name_cn',
        MAX(ip_province_en) AS 'name_en',
        SUM(request_times) AS request_times,SUM(attack_times) AS attack_times,SUM(block_times) AS block_times,
        SUM(block_times_attack) AS block_times_attack, SUM(block_times_captcha) AS block_times_captcha, SUM(block_times_cc) AS block_times_cc, SUM(captcha_pass_times) AS captcha_pass_times
    FROM traffic_stats_province_daily
    WHERE site_id = @SITE_ID@
      AND request_date >= CURDATE() - INTERVAL @DAYS@ DAY
      AND request_date <= CURDATE()
      AND ip_country_code IN ('CN', 'HK', 'MO', 'TW')
      AND ip_province_cn NOT IN ('', '未知', 'unknown')
    GROUP BY name_cn;
]]

-- 攻击类型历史只有 attack_log 有记录；@SITE_FILTER@ 由站点域名列表生成
local SQL_GET_ATTACK_TYPE_STATS = [[
    SELECT attack_type, COUNT(*) AS `value`
    FROM attack_log
    WHERE request_time >= CURDATE() - INTERVAL @DAYS@ DAY
      AND request_time < CURDATE() + INTERVAL 1 DAY
      @SITE_FILTER@
    GROUP BY attack_type
    ORDER BY `value` DESC;
]]

local SQL_CREATE_TABLE_ATTACK_LOG = [[
    CREATE TABLE `attack_log` (
        `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        `request_id` CHAR(20) NOT NULL COMMENT '请求id',

        `ip` varchar(39) NOT NULL COMMENT 'ip地址',
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
        `user_agent` VARCHAR(255) NULL COMMENT '请求客户端ua',
        `referer` VARCHAR(2048) NULL COMMENT 'referer',

        `request_protocol` VARCHAR(50) NULL COMMENT '请求协议',
        `request_uri` VARCHAR(2048) NULL COMMENT '请求uri',
        `request_body` MEDIUMTEXT NULL COMMENT '请求体',
        `http_status` SMALLINT UNSIGNED NOT NULL COMMENT 'http响应状态码',
        `response_body` MEDIUMTEXT NULL COMMENT '响应体',
        `request_time` datetime NOT NULL,

        `attack_type` VARCHAR(200) NULL COMMENT '攻击类型',
        `severity_level` VARCHAR(20) NULL COMMENT '危险级别',
        `security_module` VARCHAR(255) NULL COMMENT '安全模块',
        `hit_rule` VARCHAR(500) NULL COMMENT '命中规则',
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
        request_body, http_status, response_body, request_time, attack_type, severity_level, security_module, hit_rule, action)
    VALUES
]]

local SQL_CREATE_TABLE_IP_BLOCK_LOG = [[
    CREATE TABLE `ip_block_log` (
        `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        `request_id` CHAR(20) NULL COMMENT '请求id',

        `ip` varchar(39) NOT NULL COMMENT 'ip地址',
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

        `block_reason` VARCHAR(200) NULL COMMENT '封禁原因',
        `start_time` datetime NOT NULL COMMENT '封禁开始时间',
        `block_duration` INT NULL COMMENT '封禁时长',
        `end_time` datetime NULL COMMENT '封禁结束时间',
        `block_times` INT NULL COMMENT '封禁请求次数',
        `action` VARCHAR(100) NULL COMMENT '处置动作',
        `unblock_time` datetime  NULL COMMENT '解封时间',

        `update_time` datetime NULL,
        `create_time` datetime DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;
]]

local SQL_INSERT_IP_BLOCK_LOG = [[
    INSERT INTO ip_block_log (
        request_id, ip, ip_country_code, ip_country_cn, ip_country_en, ip_province_code, ip_province_cn, ip_province_en, ip_city_code, ip_city_cn, ip_city_en,
        ip_longitude, ip_latitude, block_reason, start_time, block_duration, end_time, action)
    VALUES
]]

function _M.check_table(premature)
    if premature then
        return
    end

    -- 大表 ADD INDEX 远超普通查询超时，按最坏情况给到 2 小时
    local DDL_TIMEOUT = 2 * 60 * 60 * 1000

    local tables = {
        {name = 'waf_status', sql = SQL_CREATE_TABLE_WAF_STATUS, indexes = {
            {name = 'idx_unique_waf_status_date_site', sql = 'ALTER TABLE waf_status ADD UNIQUE INDEX idx_unique_waf_status_date_site (request_date, site_id)'},
        }},
        {name = 'traffic_stats', sql = SQL_CREATE_TABLE_TRAFFIC_STATS, indexes = {
            {name = 'idx_unique_traffic_stats_request_date', sql = 'ALTER TABLE traffic_stats ADD UNIQUE INDEX idx_unique_traffic_stats_request_date (ip_country_code, ip_province_en, ip_city_en, request_date)'},
            {name = 'idx_traffic_stats_request_date', sql = 'ALTER TABLE traffic_stats ADD INDEX idx_traffic_stats_request_date (request_date, ip_country_code)'},
        }},
        {name = 'traffic_stats_country_daily', sql = SQL_CREATE_TABLE_TRAFFIC_STATS_COUNTRY_DAILY, indexes = {
            {name = 'idx_unique_traffic_stats_country_daily', sql = 'ALTER TABLE traffic_stats_country_daily ADD UNIQUE INDEX idx_unique_traffic_stats_country_daily (request_date, site_id, ip_country_code, ip_country_en)'},
        }},
        {name = 'traffic_stats_province_daily', sql = SQL_CREATE_TABLE_TRAFFIC_STATS_PROVINCE_DAILY, indexes = {
            {name = 'idx_unique_traffic_stats_province_daily', sql = 'ALTER TABLE traffic_stats_province_daily ADD UNIQUE INDEX idx_unique_traffic_stats_province_daily (request_date, site_id, ip_country_code, ip_province_code, ip_province_en)'},
        }},
        {name = 'attack_log', sql = SQL_CREATE_TABLE_ATTACK_LOG, indexes = {
            -- 纯时间范围统计使用单列索引，复合索引的 attack_type 会让索引项过大
            {name = 'idx_attack_log_request_time', sql = 'ALTER TABLE attack_log ADD INDEX idx_attack_log_request_time (request_time)'},
            -- 7/30 天攻击类型按时间范围 + 类型分组：覆盖索引，避免按类型全量扫索引或回表
            {name = 'idx_attack_log_request_time_type', sql = 'ALTER TABLE attack_log ADD INDEX idx_attack_log_request_time_type (request_time, attack_type)'},
            {name = 'idx_attack_log_server_name', sql = 'ALTER TABLE attack_log ADD INDEX idx_attack_log_server_name (server_name, request_time)'},
            {name = 'idx_attack_log_server_type_time', sql = 'ALTER TABLE attack_log ADD INDEX idx_attack_log_server_type_time (server_name, attack_type, request_time, action)'},
            {name = 'idx_attack_log_attack_type_time', sql = 'ALTER TABLE attack_log ADD INDEX idx_attack_log_attack_type_time (attack_type, request_time)'},
            {name = 'idx_attack_log_action_time', sql = 'ALTER TABLE attack_log ADD INDEX idx_attack_log_action_time (action, request_time)'},
            -- 攻击类型 + 处置动作组合筛选
            {name = 'idx_attack_log_type_action_time', sql = 'ALTER TABLE attack_log ADD INDEX idx_attack_log_type_action_time (attack_type, action, request_time)'},
            -- IP 精确筛选 + 时间范围，避免先取该 IP 全部历史再回表过滤时间
            {name = 'idx_attack_log_ip_time', sql = 'ALTER TABLE attack_log ADD INDEX idx_attack_log_ip_time (ip, request_time)'},
        }},
        {name = 'ip_block_log', sql = SQL_CREATE_TABLE_IP_BLOCK_LOG, indexes = {
            {name = 'idx_unique_ip_block_log_ip_start_time', sql = 'ALTER TABLE ip_block_log ADD UNIQUE INDEX idx_unique_ip_block_log_ip_start_time (ip, start_time)'},
            {name = 'idx_ip_block_log_start_time', sql = 'ALTER TABLE ip_block_log ADD INDEX idx_ip_block_log_start_time (start_time)'},
            {name = 'idx_ip_block_log_block_reason_time', sql = 'ALTER TABLE ip_block_log ADD INDEX idx_ip_block_log_block_reason_time (block_reason, start_time)'},
        }},
    }

    for _, t in pairs(tables) do
        local name = t.name
        local sql = t.sql

        local res, err = mysql.query(format(SQL_CHECK_TABLE, database, name))
        if res and res[1] then
            if res[1].c == '0' then
                res, err = mysql.query(sql, nil, DDL_TIMEOUT)
                if not res then
                    ngx.log(ngx.ERR, 'failed to create table ' .. name .. ' ', err)
                end
            end

            -- 兼容存量表：索引不存在时补建，已存在则跳过，可重复执行
            for _, idx in ipairs(t.indexes or {}) do
                local r = mysql.query(format(SQL_CHECK_INDEX, name, idx.name))
                if r and r[1] and r[1].c == '0' then
                    local ok = mysql.query(idx.sql, nil, DDL_TIMEOUT)
                    if not ok then
                        ngx.log(ngx.ERR, 'failed to create index ', idx.name, ' on table ', name)
                    end
                end
            end
        end
    end
end

-- 按保留期分批删除过期攻击日志，避免一次性删除大量行拖慢数据库
function _M.purge_attack_log(premature)
    if premature then
        return
    end

    local attack_log = get_system_config('attackLog')
    local days = tonumber(attack_log and attack_log.retentionDays) or PURGE_DEFAULT_DAYS
    if days < 1 then
        days = PURGE_DEFAULT_DAYS
    end

    local purge_sql = format(SQL_DELETE_EXPIRED_ATTACK_LOG, days, PURGE_BATCH_SIZE)
    local deleted = 0
    local batches = 0

    -- 单次运行设上限：首次部署存量很大时不会长时间占用数据库，剩余部分下次继续
    while batches < PURGE_MAX_BATCHES do
        local res, err = mysql.query(purge_sql)
        if not res then
            ngx.log(ngx.ERR, 'failed to purge attack_log: ', err)
            break
        end

        local affected = res.affected_rows or 0
        deleted = deleted + affected
        batches = batches + 1

        if affected < PURGE_BATCH_SIZE then
            break
        end

        -- 让出事件循环，也避免长时间持续压满数据库 IO
        ngx.sleep(0.05)
    end

    if deleted > 0 then
        ngx.log(ngx.INFO, 'attack_log retention: deleted ', deleted, ' rows older than ', days, ' days')
    end

    if batches >= PURGE_MAX_BATCHES then
        ngx.log(ngx.WARN, 'attack_log retention: batch limit reached, remaining rows will be purged next run')
    end
end

local TRAFFIC_STATS_BATCH_SIZE = 200
-- 归零后的 key 保留 1 小时，覆盖 30 秒采集周期，避免零值 key 长期占用共享字典
local TRAFFIC_STATS_KEY_TTL = 3600
-- 城市计数 key 带站点维度：{site_id}:{9个地理字段}:{指标}，site_id=0 表示未匹配到站点
-- ngx.re 用的是 PCRE，数字类必须写 \\d（%d 是 Lua 模式语法，PCRE 里只会匹配字面量 %d）
local CITY_KEY_PATTERN = '^(\\d+):(.*?)_(.*?)_(.*?)_(.*?)_(.*?)_(.*?)_(.*?)_(.*?)_(.*?):'
-- 不带站点前缀的旧 key 按 site_id=0 解析
local CITY_KEY_PATTERN_LEGACY = '^(.*?)_(.*?)_(.*?)_(.*?)_(.*?)_(.*?)_(.*?)_(.*?)_(.*?):'
local CITY_ROW_FORMAT = '(%s, %s, %s, %s, %s, %s, %s, %s, %s, %u, %u, %u, %u, %u, %u, %u, %s)'
-- request_date, site_id, server_name, 国家字段, 各项计数
local COUNTRY_ROW_FORMAT = '(%s, %u, %s, %s, %s, %s, %u, %u, %u, %u, %u, %u, %u)'
-- request_date, site_id, server_name, 国家代码, 省份字段, 各项计数
local PROVINCE_ROW_FORMAT = '(%s, %u, %s, %s, %s, %s, %s, %u, %u, %u, %u, %u, %u, %u)'

-- 站点id -> 主域名，落库时冗余保存，站点删除后仍能识别数据归属
local function get_site_name_map()
    local map = {}
    for _, site in ipairs(config.get_sites()) do
        map[site.id] = (site.serverNames and site.serverNames[1]) or ''
    end
    return map
end

-- 站点id -> 全部域名，attack_log 只有 server_name，按站点查询时用它生成 IN 条件
local function get_site_server_names(site_id)
    for _, site in ipairs(config.get_sites()) do
        if site.id == site_id then
            return site.serverNames or {}
        end
    end
end

local function new_stats_acc(code, cn, en, site_id)
    return {
        site_id = site_id or 0,
        code = code or '',
        cn = cn or '',
        en = en or '',
        request = 0,
        attack = 0,
        block_attack = 0,
        block_captcha = 0,
        block_cc = 0,
        captcha_pass = 0
    }
end

local function add_stats_acc(acc, request_times, attack_times, block_times_attack, block_times_captcha, block_times_cc, captcha_pass_times)
    acc.request = acc.request + request_times
    acc.attack = acc.attack + attack_times
    acc.block_attack = acc.block_attack + block_times_attack
    acc.block_captcha = acc.block_captcha + block_times_captcha
    acc.block_cc = acc.block_cc + block_times_cc
    acc.captcha_pass = acc.captcha_pass + captcha_pass_times
end

local function exec_stats_batch(head, tail, rows, count, table_name)
    if count == 0 then
        return
    end

    local sql = head .. concat(rows, ',', 1, count) .. tail
    local res, err = mysql.query(sql)
    if not res then
        ngx.log(ngx.ERR, 'failed to update ', table_name, ': ', err)
    end
end

function _M.update_traffic_stats()
    local dict = ngx.shared.dict_req_count_citys

    -- get_keys(0) 表示不限制数量；该函数每 30 秒在 timer 中执行一次，短暂阻塞可接受
    local keys = dict:get_keys(0)
    if not keys or #keys == 0 then
        return
    end

    -- ngx.today() 返回 YYYY-MM-DD，可直接写入 DATE 列
    local today = ngx.today()
    local site_names = get_site_name_map()
    local seen = {}
    local city_accs = {}
    local country_accs = {}
    local province_accs = {}
    local site_country_accs = {}
    local site_province_accs = {}

    for _, key in ipairs(keys) do
        local m = ngxmatch(key, CITY_KEY_PATTERN, 'jo')
        local offset = 2
        local site_id = 0

        if m then
            site_id = tonumber(m[1]) or 0
        else
            m = ngxmatch(key, CITY_KEY_PATTERN_LEGACY, 'jo')
            offset = 1
        end

        if m then
            local prefix = m[0]

            -- 每个城市有 6 个计数 key，按城市前缀去重，避免重复读取和重复计数。
            if not seen[prefix] then
                seen[prefix] = true

                local request_times = utils.dict_get(dict, prefix .. constants.KEY_REQUEST_TIMES) or 0
                local attack_times = utils.dict_get(dict, prefix .. constants.KEY_ATTACK_TIMES) or 0
                local block_times_attack = utils.dict_get(dict, prefix .. constants.KEY_BLOCK_TIMES_ATTACK) or 0
                local block_times_captcha = utils.dict_get(dict, prefix .. constants.KEY_BLOCK_TIMES_CAPTCHA) or 0
                local block_times_cc = utils.dict_get(dict, prefix .. constants.KEY_BLOCK_TIMES_CC) or 0
                local captcha_pass_times = utils.dict_get(dict, prefix .. constants.KEY_CAPTCHA_PASS_TIMES) or 0

                if request_times > 0 or attack_times > 0 or block_times_attack > 0 or block_times_captcha > 0 or block_times_cc > 0 or captcha_pass_times > 0 then
                    -- 重置时带上 TTL；不带 TTL 的 set 会清除过期时间，历史城市 key 会永久占用共享字典。
                    utils.dict_set(dict, prefix .. constants.KEY_REQUEST_TIMES, 0, TRAFFIC_STATS_KEY_TTL)
                    utils.dict_set(dict, prefix .. constants.KEY_ATTACK_TIMES, 0, TRAFFIC_STATS_KEY_TTL)
                    utils.dict_set(dict, prefix .. constants.KEY_BLOCK_TIMES_ATTACK, 0, TRAFFIC_STATS_KEY_TTL)
                    utils.dict_set(dict, prefix .. constants.KEY_BLOCK_TIMES_CAPTCHA, 0, TRAFFIC_STATS_KEY_TTL)
                    utils.dict_set(dict, prefix .. constants.KEY_BLOCK_TIMES_CC, 0, TRAFFIC_STATS_KEY_TTL)
                    utils.dict_set(dict, prefix .. constants.KEY_CAPTCHA_PASS_TIMES, 0, TRAFFIC_STATS_KEY_TTL)

                    local country_code = m[offset] or ''
                    local country_cn = m[offset + 1] or ''
                    local country_en = m[offset + 2] or ''
                    local province_code = m[offset + 3] or ''
                    local province_cn = m[offset + 4] or ''
                    local province_en = m[offset + 5] or ''
                    local city_code = m[offset + 6] or ''
                    local city_cn = m[offset + 7] or ''
                    local city_en = m[offset + 8] or ''

                    -- 兜底归一化：个别 IP 库记录缺少 iso_code，只有英文名。
                    -- 只补空 code，不改动已有 code，也不改变国家归属：
                    --   * 避免同一地区在汇总表里被拆成“有 code / 无 code”两行
                    --   * 空 code 的香港/澳门补回 HK/MO 后，dashboard 才能正确落到地图上
                    if country_code == '' then
                        if country_en == 'Hong Kong' then
                            country_code = 'HK'
                        elseif country_en == 'Macao' then
                            country_code = 'MO'
                        end
                    end
                    if province_code == '' then
                        if province_en == 'Hong Kong' then
                            province_code = 'HK'
                        elseif province_en == 'Macao' then
                            province_code = 'MO'
                        end
                    end

                    -- 城市级明细：只保留全局粒度，按地理字段合并多个站点的计数
                    local city_key = concat({country_code, country_cn, country_en, province_code, province_cn, province_en, city_code, city_cn, city_en}, '\1')
                    local city = city_accs[city_key]
                    if not city then
                        city = new_stats_acc(country_code, country_cn, country_en)
                        city.geo = {country_code, country_cn, country_en, province_code, province_cn, province_en, city_code, city_cn, city_en}
                        city_accs[city_key] = city
                    end
                    add_stats_acc(city, request_times, attack_times, block_times_attack, block_times_captcha, block_times_cc, captcha_pass_times)

                    -- 国家级汇总（唯一键为 code + en，避免中文名偶发为空时拆成两行）
                    local country_key = country_code .. '\1' .. country_en
                    local country = country_accs[country_key]
                    if not country then
                        country = new_stats_acc(country_code, country_cn, country_en)
                        country_accs[country_key] = country
                    end
                    add_stats_acc(country, request_times, attack_times, block_times_attack, block_times_captcha, block_times_cc, captcha_pass_times)

                    -- 省级汇总（唯一键为 code + en；空 code 的香港/澳门/未知靠 en 区分）
                    local province_key = country_code .. '\1' .. province_code .. '\1' .. province_en
                    local province = province_accs[province_key]
                    if not province then
                        province = new_stats_acc(province_code, province_cn, province_en)
                        province.country_code = country_code
                        province_accs[province_key] = province
                    end
                    add_stats_acc(province, request_times, attack_times, block_times_attack, block_times_captcha, block_times_cc, captcha_pass_times)

                    -- 站点维度：未匹配到站点配置的请求（site_id=0）只计入全局行
                    if site_id > 0 then
                        local skey = site_id .. '\1' .. country_key
                        local site_country = site_country_accs[skey]
                        if not site_country then
                            site_country = new_stats_acc(country_code, country_cn, country_en, site_id)
                            site_country_accs[skey] = site_country
                        end
                        add_stats_acc(site_country, request_times, attack_times, block_times_attack, block_times_captcha, block_times_cc, captcha_pass_times)

                        skey = site_id .. '\1' .. province_key
                        local site_province = site_province_accs[skey]
                        if not site_province then
                            site_province = new_stats_acc(province_code, province_cn, province_en, site_id)
                            site_province.country_code = country_code
                            site_province_accs[skey] = site_province
                        end
                        add_stats_acc(site_province, request_times, attack_times, block_times_attack, block_times_captcha, block_times_cc, captcha_pass_times)
                    end
                end
            end
        end
    end

    -- 城市级明细（全局），按批写入避免单条 SQL 过大
    local city_rows = newtab(TRAFFIC_STATS_BATCH_SIZE, 0)
    local city_count = 0
    for _, c in pairs(city_accs) do
        local geo = c.geo
        city_count = city_count + 1
        city_rows[city_count] = format(CITY_ROW_FORMAT,
            quote_sql_str(geo[1]), quote_sql_str(geo[2]), quote_sql_str(geo[3]),
            quote_sql_str(geo[4]), quote_sql_str(geo[5]), quote_sql_str(geo[6]),
            quote_sql_str(geo[7]), quote_sql_str(geo[8]), quote_sql_str(geo[9]),
            c.request, c.attack, c.block_attack + c.block_captcha + c.block_cc,
            c.block_attack, c.block_captcha, c.block_cc, c.captcha_pass,
            quote_sql_str(today))

        if city_count >= TRAFFIC_STATS_BATCH_SIZE then
            exec_stats_batch(SQL_INSERT_TRAFFIC_STATS_HEAD, SQL_INSERT_TRAFFIC_STATS_TAIL, city_rows, city_count, 'traffic_stats')
            city_rows = newtab(TRAFFIC_STATS_BATCH_SIZE, 0)
            city_count = 0
        end
    end
    exec_stats_batch(SQL_INSERT_TRAFFIC_STATS_HEAD, SQL_INSERT_TRAFFIC_STATS_TAIL, city_rows, city_count, 'traffic_stats')

    -- 国家/省份：全局行（site_id=0）+ 每个站点一行
    local country_rows = newtab(256, 0)
    local country_count = 0
    for _, c in pairs(country_accs) do
        country_count = country_count + 1
        country_rows[country_count] = format(COUNTRY_ROW_FORMAT,
            quote_sql_str(today), 0, quote_sql_str(''),
            quote_sql_str(c.code), quote_sql_str(c.cn), quote_sql_str(c.en),
            c.request, c.attack, c.block_attack + c.block_captcha + c.block_cc,
            c.block_attack, c.block_captcha, c.block_cc, c.captcha_pass)
    end
    for _, c in pairs(site_country_accs) do
        country_count = country_count + 1
        country_rows[country_count] = format(COUNTRY_ROW_FORMAT,
            quote_sql_str(today), c.site_id, quote_sql_str(site_names[c.site_id] or ''),
            quote_sql_str(c.code), quote_sql_str(c.cn), quote_sql_str(c.en),
            c.request, c.attack, c.block_attack + c.block_captcha + c.block_cc,
            c.block_attack, c.block_captcha, c.block_cc, c.captcha_pass)
    end
    exec_stats_batch(SQL_INSERT_TRAFFIC_STATS_COUNTRY_HEAD, SQL_INSERT_TRAFFIC_STATS_COUNTRY_TAIL, country_rows, country_count, 'traffic_stats_country_daily')

    local province_rows = newtab(256, 0)
    local province_count = 0
    for _, p in pairs(province_accs) do
        province_count = province_count + 1
        province_rows[province_count] = format(PROVINCE_ROW_FORMAT,
            quote_sql_str(today), 0, quote_sql_str(''),
            quote_sql_str(p.country_code), quote_sql_str(p.code), quote_sql_str(p.cn), quote_sql_str(p.en),
            p.request, p.attack, p.block_attack + p.block_captcha + p.block_cc,
            p.block_attack, p.block_captcha, p.block_cc, p.captcha_pass)
    end
    for _, p in pairs(site_province_accs) do
        province_count = province_count + 1
        province_rows[province_count] = format(PROVINCE_ROW_FORMAT,
            quote_sql_str(today), p.site_id, quote_sql_str(site_names[p.site_id] or ''),
            quote_sql_str(p.country_code), quote_sql_str(p.code), quote_sql_str(p.cn), quote_sql_str(p.en),
            p.request, p.attack, p.block_attack + p.block_captcha + p.block_cc,
            p.block_attack, p.block_captcha, p.block_cc, p.captcha_pass)
    end
    exec_stats_batch(SQL_INSERT_TRAFFIC_STATS_PROVINCE_HEAD, SQL_INSERT_TRAFFIC_STATS_PROVINCE_TAIL, province_rows, province_count, 'traffic_stats_province_daily')
end

local WAF_STATUS_METRICS = {
    constants.KEY_HTTP_4XX, constants.KEY_HTTP_5XX, constants.KEY_REQUEST_TIMES, constants.KEY_ATTACK_TIMES,
    constants.KEY_BLOCK_TIMES_ATTACK, constants.KEY_BLOCK_TIMES_CAPTCHA, constants.KEY_BLOCK_TIMES_CC, constants.KEY_CAPTCHA_PASS_TIMES
}

-- 归零后带 1 小时 TTL，避免零值 key 永久占用共享字典
local WAF_STATUS_KEY_TTL = 3600

-- 读取并清零一组计数，全为 0 时返回 nil
local function take_waf_status(dict, prefix)
    local values = {}
    local total = 0

    for i = 1, #WAF_STATUS_METRICS do
        local value = utils.dict_get(dict, prefix .. WAF_STATUS_METRICS[i]) or 0
        values[i] = value
        total = total + value
    end

    if total == 0 then
        return nil
    end

    for i = 1, #WAF_STATUS_METRICS do
        utils.dict_set(dict, prefix .. WAF_STATUS_METRICS[i], 0, WAF_STATUS_KEY_TTL)
    end

    return values
end

function _M.update_waf_status()
    local dict = ngx.shared.dict_req_count

    -- 全局计数为 0 时各站点必然也为 0，直接返回，避免每 2 秒遍历全部站点
    local values = take_waf_status(dict, '')
    if not values then
        return
    end

    local today = quote_sql_str(ngx.today())
    local rows = newtab(64, 0)
    local count = 0

    local function append_row(site_id, server_name, v)
        count = count + 1
        rows[count] = format(WAF_STATUS_ROW_FORMAT, site_id, quote_sql_str(server_name),
            v[1], v[2], v[3], v[4], v[5] + v[6] + v[7], v[5], v[6], v[7], v[8], today)
    end

    append_row(0, '', values)

    local site_names = get_site_name_map()
    for _, site in ipairs(config.get_sites()) do
        local site_values = take_waf_status(dict, 's' .. tostring(site.id) .. ':')
        if site_values then
            append_row(site.id, site_names[site.id] or '', site_values)
        end
    end

    local sql = SQL_INSERT_WAF_STATUS_HEAD .. concat(rows, ',', 1, count) .. SQL_INSERT_WAF_STATUS_TAIL
    mysql.query(sql)
end

-- site_id 是 INT UNSIGNED：过滤 nan/inf/负数/超上限，避免拼出 site_id = inf 这类非法 SQL
local INT_UNSIGNED_MAX = 4294967295

local function normalize_site_id(value)
    local id = tonumber(value)
    if not id or id ~= id then
        return 0
    end

    id = floor(id)
    if id < 0 then
        return 0
    end
    if id > INT_UNSIGNED_MAX then
        return INT_UNSIGNED_MAX
    end
    return id
end

function _M.normalize_site_id(value)
    return normalize_site_id(value)
end

-- resty.mysql 的 db:query 第二个参数是预估行数，不支持 ? 参数绑定，
-- 站点id 统一转成非负整数后再直接拼进 SQL
local function bind_site_id(sql, site_id)
    return (gsub(sql, '@SITE_ID@', tostring(normalize_site_id(site_id))))
end

-- @DAYS@ 只接受非负整数，避免拼出非法 SQL
local function bind_days(sql, days)
    local d = floor(tonumber(days) or 0)
    if d < 0 or d ~= d then
        d = 0
    end
    return (gsub(sql, '@DAYS@', tostring(d)))
end

local function build_attack_log_site_filter(site_id)
    local id = normalize_site_id(site_id)
    if id == 0 then
        return ''
    end

    local names = get_site_server_names(id)
    if not names or #names == 0 then
        return 'AND 1 = 0'
    end

    local quoted = newtab(#names, 0)
    for i = 1, #names do
        quoted[i] = quote_sql_str(names[i])
    end
    return 'AND server_name IN (' .. concat(quoted, ',', 1, #names) .. ')'
end

function _M.get_today_waf_status(site_id)
    return mysql.query(bind_site_id(SQL_GET_TODAY_WAF_STATUS, site_id))
end

function _M.get_range_waf_status(site_id, days)
    return mysql.query(bind_site_id(bind_days(SQL_GET_RANGE_WAF_STATUS, days), site_id))
end

function _M.get_range_traffic_stats(site_id, days)
    return mysql.query(bind_site_id(bind_days(SQL_GET_RANGE_TRAFFIC_STATS, days), site_id))
end

function _M.get_range_world_traffic_stats(site_id, days)
    return mysql.query(bind_site_id(bind_days(SQL_GET_RANGE_WORLD_TRAFFIC_STATS, days), site_id))
end

function _M.get_range_china_traffic_stats(site_id, days)
    return mysql.query(bind_site_id(bind_days(SQL_GET_RANGE_CHINA_TRAFFIC_STATS, days), site_id))
end

function _M.get_attack_type_stats(site_id, days)
    local query = bind_days(SQL_GET_ATTACK_TYPE_STATS, days)
    local filter = build_attack_log_site_filter(site_id)
    query = gsub(query, '@SITE_FILTER@', function()
        return filter
    end)
    return mysql.query(query)
end

function _M.write_sql_queue_to_mysql(premature, key)
    if premature or not key then
        return
    end

    local dict_sql_queue = ngx.shared.dict_sql_queue

    -- 只处理进入函数时的快照数量，避免高流量下 timer 长时间不返回
    local remaining = dict_sql_queue:llen(key) or 0
    if remaining == 0 then
        return
    end

    local sql_str
    if key == constants.KEY_ATTACK_LOG then
        sql_str = SQL_INSERT_ATTACK_LOG
    elseif key == constants.KEY_IP_BLOCK_LOG then
        sql_str = SQL_INSERT_IP_BLOCK_LOG
    else
        return
    end

    local buffer = newtab(BATCH_SIZE, 0)
    local index = 0
    local bytes = 0

    local function flush()
        if index == 0 then
            return
        end

        mysql.query(sql_str .. concat(buffer, ',', 1, index))
        buffer = newtab(BATCH_SIZE, 0)
        index = 0
        bytes = 0
    end

    while remaining > 0 do
        local value = dict_sql_queue:lpop(key)
        if not value then
            break
        end
        remaining = remaining - 1

        index = index + 1
        buffer[index] = value
        bytes = bytes + #value

        if index >= BATCH_SIZE or bytes >= BATCH_MAX_BYTES then
            flush()
        end
    end

    flush()
end

function _M.write_sql_to_queue(key, sql)
    local dict_sql_queue = ngx.shared.dict_sql_queue
    local ok, err = dict_sql_queue:rpush(key, sql)
    if not ok then
        ngx.log(ngx.ERR, "failed to push sql to queue ", key, ": ", err)
    end
end

return _M
