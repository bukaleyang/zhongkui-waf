local config = require "config"
local time = require "time"

local gsub = string.gsub
local ipairs = ipairs
local concat = table.concat
local ngxfind = ngx.re.find

local ATTACK_PREFIX = "attack_"
local ATTACK_TYPE_PREFIX = "attack_type_"

local function getRequestTraffic()
    local hours = time.getHours()
    local dict = ngx.shared.dict_req_count
    local dataStr = "['hour', 'traffic','attack_traffic'],"
    for _, hour in ipairs(hours) do
        local count = dict:get(hour) or 0
        local attackCount = dict:get(ATTACK_PREFIX .. hour) or 0
        dataStr = concat({ dataStr, "['", hour, "', ", count, ",", attackCount, "]," })
    end

    return dataStr
end

local function getAttackTypeTraffic()
    local dict = ngx.shared.dict_req_count
    local keys = dict:get_keys()
    local dataStr = ''

    if keys then
        local today = ngx.today()
        local prefix = ATTACK_TYPE_PREFIX .. today

        for _, key in ipairs(keys) do
            local from = ngxfind(key, prefix)
            if from then
                local count = dict:get(key) or 0
                dataStr = concat({ dataStr, "{name:'", key, "',value: ", count, "}," })
            end
        end
    end

    return dataStr
end

if config.isWAFOn and config.isDashboardOn then
    local html = config.dashboardHtml
    local trafficDataStr = getRequestTraffic()
    local attackTypeDataStr = getAttackTypeTraffic()

    html = gsub(html, "#trafficData#", trafficDataStr)
    html = gsub(html, "#attackTypeData#", attackTypeDataStr)

    ngx.header.content_type = "text/html; charset=UTF-8"
    ngx.status = ngx.HTTP_OK
    ngx.say(html)

    return ngx.exit(ngx.status)
end
