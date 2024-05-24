-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local geo = require "resty.maxminddb"
local config = require "config"
local ipUtils = require "ip"

local _M = {}

local pcall = pcall
local next = next
local ipairs = ipairs

local dbFile = config.get('geoip_db_file')
local disallowCountryList = config.get('geoip_disallow_country') or {}
local disallowCountryTable = nil

local unknown = {['iso_code'] = ''}
local unknownNames = {en = 'unknown', ['zh-CN'] = '未知'}
unknown.names = unknownNames

local default = {isAllowed = true, country = unknown, province = unknown, city = unknown, longitude = 0, latitude = 0}

local intranet = {isAllowed = true, longitude = 0, latitude = 0,
                country = {names = {['iso_code'] = '', en = 'intranet', ['zh-CN'] = '内网'}},
                province = {names = {['iso_code'] = '', en = 'intranet', ['zh-CN'] = '内网'}},
                city = {names = {['iso_code'] = '', en = 'intranet', ['zh-CN'] = '内网'}}}

function _M.lookup(ip)
    if not config.isGeoIPOn then
        return default
    end

    if ipUtils.isPrivateIP(ip) then
        return intranet
    end

    if not geo.initted() then
        geo.init(dbFile)

        if next(disallowCountryList) ~= nil then
            disallowCountryTable = {}
            for _, code in ipairs(disallowCountryList) do
                disallowCountryTable[code] = 1
            end
        end
    end

    local isAllowed = true
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

        if disallowCountryTable then
            if disallowCountryTable[iso_code] then
                isAllowed = false
            end
        end

        if iso_code == 'TW' or iso_code == 'HK' or iso_code == 'MO' then
            local cnName = country.names['zh-CN']
            local enName = country.names['en']

            province.iso_code = iso_code
            province.names['zh-CN'] = cnName
            province.names['en'] = enName

            if iso_code ~= 'TW' then
                city.iso_code = ''
                city.names['zh-CN'] = cnName
                city.names['en'] = enName
            end
            country.iso_code = 'CN'
            country.names['zh-CN'] = '中国'
            country.names['en'] = 'China'
        end
    end

    return { isAllowed = isAllowed, country = country, province = province, city = city, longitude = longitude or 0, latitude = latitude or 0 }
end

return _M
