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
local language = config.get("geoip_language") ~= '' and config.get("geoip_language") or 'en'
local disallowCountryTable = nil

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

    --support ipv6 e.g. 2001:4860:0:1001::3004:ef68
    local pass, res, err = pcall(geo.lookup, ip)
    if not pass then
        ngx.log(ngx.ERR, 'failed to lookup by ip,reason:', res)
    else
        if not res then
            ngx.log(ngx.ERR, 'failed to lookup by ip,reason:', err)
        else
            local countryRes = res['country']
            if countryRes then
                local names = countryRes['names']
                if names then
                    country = names[language] or ''
                end
            end

            local subdivisions = res['subdivisions']
            if subdivisions then
                local subdivisions1 = subdivisions[1]
                if subdivisions1 then
                    local names = subdivisions1['names']
                    if names then
                        province = names[language] or ''
                    end
                end
            end

            local cityRes = res['city']
            if cityRes then
                local names = cityRes['names']
                city = names[language] or ''
            end

            if disallowCountryTable then
                local iso_code = res['country']['iso_code']

                if disallowCountryTable[iso_code] then
                    isAllowed = false
                end
            end
        end
    end

    return { isAllowed = isAllowed, country = country or '', province = province or '', city = city or '' }
end

return _M
