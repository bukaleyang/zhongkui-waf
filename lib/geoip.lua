-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local geo = require "resty.maxminddb"
local config = require "config"

local _M = {}

local pcall = pcall
local next = next
local ipairs = ipairs

local dbFile = config.get('geoip_db_file')
local disallowCountryList = config.get('geoip_disallow_country') or {}
local disallowCountryTable = nil

local unknown = {}
local unknownNames = {en = 'unknown'}
unknownNames['zh-CN'] = 'unknown'
unknown['iso_code'] = 'unknown'
unknown.names = unknownNames

function _M.lookup(ip)
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
    if not pass then
        ngx.log(ngx.ERR, 'failed to lookup by ip,reason:', err)
    else
        if not res then
            ngx.log(ngx.ERR, 'failed to lookup by ip,reason:', err)
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

            local iso_code = country.iso_code

            local subdivisions = res['subdivisions']
            if subdivisions then
                province = subdivisions[1]
                if province then
                    local names = province['names']
                    if not names then
                        province['names'] = unknownNames
                    end
                else
                    province = unknown
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
    end

    return { isAllowed = isAllowed, country = country or {names = unknownNames}, province = province or unknown, city = city or unknown, longitude = longitude or 0, latitude = latitude or 0 }
end

return _M
