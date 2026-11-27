-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local config = require "config"
local cjson = require "cjson"
local user = require "user"
local time = require "time"
local sql = require "sql"
local utils = require "utils"
local constants = require "constants"

local ipairs = ipairs
local concat = table.concat
local sort = table.sort
local tonumber = tonumber
local tostring = tostring

local cjson_encode = cjson.encode
local is_system_option_on = config.is_system_option_on

local _M = {}

-- 近 7 天含今天共 7 天，SQL 向前偏移 6 天；近 30 天同理偏移 29 天
local RANGE_DAYS = { ['7d'] = 6, ['30d'] = 29 }

-- 按 nginx 本地时间生成日期，和写入 waf_status/attack_log 的时区保持一致
local DAY_SECONDS = 86400
local function date_offset(days)
    return os.date('%Y-%m-%d', ngx.time() - days * DAY_SECONDS)
end

local function getRequestTraffic(site_prefix)
    local hours = time.get_hours()
    local dict = ngx.shared.dict_req_count
    local dataStr = '[["hour", "traffic","attack_traffic","blocked_traffic"],'
    for _, hour in ipairs(hours) do
        local count = dict:get(site_prefix .. hour) or 0
        local attack_count = dict:get(site_prefix .. constants.KEY_ATTACK_PREFIX .. hour) or 0
        local blocked_count = dict:get(site_prefix .. constants.KEY_BLOCKED_PREFIX .. hour) or 0
        dataStr = concat({ dataStr, '["', hour, '", ', count, ',', attack_count, ',', blocked_count, '],' })
    end

    dataStr = string.sub(dataStr, 1, -2) .. ']'
    return dataStr
end

local function getAttackTypeTraffic(site_prefix)
    local dict = ngx.shared.dict_req_count
    -- 键里含站点前缀，用 get_keys(0) 避免默认 1024 上限导致部分攻击类型漏统计
    local keys = dict:get_keys(0)
    local items = {}

    if keys then
        local today = ngx.today()
        -- 键格式为 attack_type_{date}_{type}，前缀要带末尾下划线，取出的攻击类型才不带 _
        local prefix = site_prefix .. constants.KEY_ATTACK_TYPE_PREFIX .. today .. '_'

        for _, key in ipairs(keys) do
            if string.sub(key, 1, #prefix) == prefix then
                local count = dict:get(key) or 0
                local attack_type = string.sub(key, #prefix + 1)
                items[#items + 1] = { name = attack_type, value = tonumber(count) or 0 }
            end
        end
    end

    if #items == 0 then
        return '[]'
    end

    sort(items, function(a, b)
        return a.value > b.value
    end)
    return cjson_encode(items)
end

-- 7/30 天拦截量取 waf_status.block_times（攻击+人机+CC）；今天取字典 blocked_<hour>，两者口径略有差异
local function getRangeTrafficData(site_id, days)
    local res, err = sql.get_range_traffic_stats(site_id, days)
    if not res then
        ngx.log(ngx.ERR, 'failed to get range traffic stats: ', err)
        return nil, err
    end

    local rows = {}
    for _, row in ipairs(res) do
        rows[row.label] = row
    end

    -- 按完整日期序列补零，某天没有数据时曲线也不会跳过该天
    local dataStr = '[["date", "traffic","attack_traffic","blocked_traffic"]'
    for offset = days, 0, -1 do
        local label = date_offset(offset)
        local row = rows[label]
        dataStr = concat({
            dataStr, ',["', label, '",',
            row and row.request_times or 0, ',',
            row and row.attack_times or 0, ',',
            row and row.block_times or 0, ']'
        })
    end

    return dataStr .. ']'
end

-- 今天走共享字典实时计数；7/30 天只有 attack_log 有历史，两者存在 2 秒 SQL 队列窗口差异
local function getRangeAttackTypeData(site_id, days)
    local res, err = sql.get_attack_type_stats(site_id, days)
    if not res then
        ngx.log(ngx.ERR, 'failed to get attack type stats: ', err)
        return nil, err
    end

    local items = {}
    for _, row in ipairs(res) do
        local name = row.attack_type
        -- attack_type 允许 NULL，lua-resty-mysql 会返回 ngx.null，不能直接交给 cjson
        if name == nil or name == ngx.null then
            name = ''
        end
        items[#items + 1] = { name = name, value = tonumber(row.value) or 0 }
    end

    if #items == 0 then
        return '[]'
    end

    return cjson_encode(items)
end

function _M.do_request()
    local response = {code = 200, data = {}, msg = ""}
    local uri = ngx.var.uri

    if user.check_auth_token() == false then
        response.code = 401
        response.msg = 'User not logged in'
        ngx.status = 401
        ngx.say(cjson_encode(response))
        ngx.exit(401)
        return
    end

    if uri == "/dashboard" then
        local args, err = ngx.req.get_uri_args()
        if not args then
            ngx.log(ngx.ERR, 'failed to get uri args: ', err)
            args = {}
        end

        -- site_id 统一成 INT UNSIGNED 范围，避免字典前缀与 SQL 查询用了不同的站点id
        local site_id = sql.normalize_site_id(args['siteId'])

        local range = args['range']
        if range ~= '7d' and range ~= '30d' then
            range = 'today'
        end

        local mysql_on = is_system_option_on("mysql")
        -- 没有 MySQL 时只有当天的字典数据
        if not mysql_on then
            range = 'today'
        end
        local days = RANGE_DAYS[range] or 0

        -- 共享字典里的站点前缀；0 表示全部站点
        local site_prefix = site_id > 0 and ('s' .. tostring(site_id) .. ':') or ''

        -- SQL 失败时明确返回错误，避免页面把“查询失败”显示成“没有流量”
        local function fail(msg)
            response.code = 500
            response.msg = msg
            ngx.say(cjson_encode(response))
        end

        local trafficDataStr
        local attackTypeDataStr
        if range == 'today' then
            trafficDataStr = getRequestTraffic(site_prefix)
            attackTypeDataStr = getAttackTypeTraffic(site_prefix)
        else
            local err
            trafficDataStr, err = getRangeTrafficData(site_id, days)
            if not trafficDataStr then
                fail('流量统计查询失败')
                return
            end

            attackTypeDataStr, err = getRangeAttackTypeData(site_id, days)
            if not attackTypeDataStr then
                fail('攻击类型查询失败')
                return
            end
        end

        local data = {}
        data.trafficData = trafficDataStr
        data.attackTypeData = attackTypeDataStr
        data.sites = config.get_sites()
        data.granularity = range == 'today' and 'hour' or 'day'
        data.mysql = mysql_on

        local wafStatus = {}
        local world = {}
        local china = {}

        if mysql_on then
            local res, err
            if range == 'today' then
                res, err = sql.get_today_waf_status(site_id)
            else
                res, err = sql.get_range_waf_status(site_id, days)
            end
            if not res then
                ngx.log(ngx.ERR, 'failed to get waf status: ', err)
                fail('统计数据查询失败')
                return
            end
            -- 所选范围没有数据时返回空表，前端按 0 显示，避免残留上一个站点的数字
            wafStatus = res[1] or {}

            res, err = sql.get_range_world_traffic_stats(site_id, days)
            if not res then
                ngx.log(ngx.ERR, 'failed to get world traffic stats: ', err)
                fail('访问来源统计查询失败')
                return
            end
            world = res

            res, err = sql.get_range_china_traffic_stats(site_id, days)
            if not res then
                ngx.log(ngx.ERR, 'failed to get china traffic stats: ', err)
                fail('访问来源统计查询失败')
                return
            end
            china = res
        else
            local dict = ngx.shared.dict_req_count

            local http4xx = utils.dict_get(dict, site_prefix .. constants.KEY_HTTP_4XX) or 0
            local http5xx = utils.dict_get(dict, site_prefix .. constants.KEY_HTTP_5XX) or 0
            local request_times = utils.dict_get(dict, site_prefix .. constants.KEY_REQUEST_TIMES) or 0
            local attack_times = utils.dict_get(dict, site_prefix .. constants.KEY_ATTACK_TIMES) or 0
            local block_times_attack = utils.dict_get(dict, site_prefix .. constants.KEY_BLOCK_TIMES_ATTACK) or 0
            local block_times_captcha = utils.dict_get(dict, site_prefix .. constants.KEY_BLOCK_TIMES_CAPTCHA) or 0
            local block_times_cc = utils.dict_get(dict, site_prefix .. constants.KEY_BLOCK_TIMES_CC) or 0
            local captcha_pass_times = utils.dict_get(dict, site_prefix .. constants.KEY_CAPTCHA_PASS_TIMES) or 0

            local block_times = block_times_attack + block_times_captcha + block_times_cc

            wafStatus = {http4xx = http4xx, http5xx = http5xx, request_times = request_times,
                        attack_times = attack_times, block_times = block_times, block_times_attack = block_times_attack,
                        block_times_captcha = block_times_captcha, block_times_cc = block_times_cc, captcha_pass_times = captcha_pass_times}
        end

        data.sourceRegion = {world = world, china = china}
        data.wafStatus = wafStatus
        response.data = data
    end

    ngx.say(cjson_encode(response))
end

_M.do_request()

return _M
