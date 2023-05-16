local geo = require "resty.maxminddb"
local config = require "config"

local _M = {}

local pcall = pcall

local dbFile = config.get('geoip_db_file')
local allowCountryList = config.get('geoip_allow_country') or {}
local language = config.get("geoip_language") ~= '' and config.get("geoip_language") or 'en'
local allowCountry = false

function _M.lookup(ip)
    if not geo.initted() then
        geo.init(dbFile)
        allowCountry = (next(allowCountryList) ~= nil)
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
    end

    return { isAllowed = isAllowed, country = country or '', province = province or '', city = city or '' }
end

return _M
