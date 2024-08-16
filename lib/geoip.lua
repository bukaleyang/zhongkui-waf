-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local geo = require "resty.maxminddb"
local config = require "config"
local ip_utils = require "ip_utils"

local _M = {}

local pcall = pcall
local next = next
local ipairs = ipairs

local get_site_config = config.get_site_config
local get_system_config = config.get_system_config
local is_private_ip = ip_utils.is_private_ip

local db_file = get_system_config().geoip.file

local unknown = {['iso_code'] = ''}
local unknownNames = {en = 'unknown', ['zh-CN'] = '未知'}
unknown.names = unknownNames

local default = {is_allowed = true, country = unknown, province = unknown, city = unknown, longitude = 0, latitude = 0}

local intranet = {is_allowed = true, longitude = 0, latitude = 0,
                country = {names = {['iso_code'] = '', en = 'intranet', ['zh-CN'] = '内网'}},
                province = {names = {['iso_code'] = '', en = 'intranet', ['zh-CN'] = '内网'}},
                city = {names = {['iso_code'] = '', en = 'intranet', ['zh-CN'] = '内网'}}}

function _M.lookup(ip)
    if is_private_ip(ip) then
        return intranet
    end

    if not geo.initted() then
        geo.init(db_file)
    end

    local disallow_country_list =  get_site_config("geoip")['disallowCountrys']
    local disallow_country_table = nil

    if next(disallow_country_list) ~= nil then
        disallow_country_table = {}
        for _, code in ipairs(disallow_country_list) do
            disallow_country_table[code] = 1
        end
    end

    local is_allowed = true
    local country = nil
    local province = nil
    local city = nil
    local longitude = nil
    local latitude = nil

    --support ipv6 e.g. 2001:4860:0:1001::3004:ef68
    local pass, res, err = pcall(geo.lookup, ip)
    if not pass or not res then
        ngx.log(ngx.ERR, 'failed to lookup by ip,reason:', err)
        return default
    else
        country = res['country']
        if country then
            local names = country['names']
            if not names then
                country['names'] = unknownNames
            end
        else
            country = unknown
            country['iso_code'] = ''
        end

        local subdivisions = res['subdivisions']
        if subdivisions then
            province = subdivisions[1]
        end

        if province then
            local names = province['names']
            if not names then
                province['names'] = unknownNames
            end
        else
            province = unknown
        end

        city = res['city']
        if city then
            local names = city['names']
            if not names then
                city['names'] = unknownNames
            end
        else
            city = unknown
        end

        local location = res['location']
        if location then
            longitude = location['longitude']
            latitude = location['latitude']
        end

        local iso_code = country.iso_code

        if disallow_country_table then
            if disallow_country_table[iso_code] then
                is_allowed = false
            end
        end

        if iso_code == 'TW' or iso_code == 'HK' or iso_code == 'MO' then
            local name_cn = country.names['zh-CN']
            local name_en = country.names['en']

            province.iso_code = iso_code
            province.names['zh-CN'] = name_cn
            province.names['en'] = name_en

            if iso_code ~= 'TW' then
                city.iso_code = ''
                city.names['zh-CN'] = name_cn
                city.names['en'] = name_en
            end
            country.iso_code = 'CN'
            country.names['zh-CN'] = '中国'
            country.names['en'] = 'China'
        end
    end

    return { is_allowed = is_allowed, country = country, province = province, city = city, longitude = longitude or 0, latitude = latitude or 0 }
end

return _M
