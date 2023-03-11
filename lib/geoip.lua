local geo = require "resty.maxminddb"
local config = require "config"

local _M = {}

local dbFile = config.get('geoip_db_file')
local allowCountryList = config.get('geoip_allow_country')
local language = config.get("geoip_language") ~= '' and config.get("geoip_language") or 'en'
local allowCountry = false

function _M.lookup(ip)
    if not geo.initted() then
        geo.init(dbFile)
        allowCountry = (next(allowCountryList) ~= nil)
    end

    local isAllowed = true
    local result = '-'

    --support ipv6 e.g. 2001:4860:0:1001::3004:ef68
    local res,err = geo.lookup(ip)

    if not res then
        ngx.log(ngx.ERR, 'failed to lookup by ip ,reason:', err)
    else
        result = res['country']['names'][language]

        local subdivisions = res['subdivisions']
        if subdivisions then
            local name = subdivisions[1]['names'][language]
            if name ~= nil then
                result = result .. name
            end
        end

        local city = res['city']
        if city then
            local name = city['names'][language]
            if name ~= nil then
                result = result .. name
            end
        end

        if allowCountry then
            local iso_code = res['country']['iso_code']
            isAllowed = false

            for _, c in ipairs(allowCountryList) do
                if iso_code == c then
                    isAllowed = true
                    break
                end
            end
        end
    end

    return {isAllowed = isAllowed, name = result}
end


return _M