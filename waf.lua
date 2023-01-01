local geoip = require("geoip")

local geoip_default = {isAllowed = true, name = '-'}

local function init()
    local ip = getClientIP()
    
    if isGeoIPOn then
        ngx.ctx.geoip = geoip.lookup(ip)
    else
        ngx.ctx.geoip = geoip_default
    end
end

if isWAFOn then
   
    init()
    
    if isWhiteIp() then

    elseif isBlackIp() then
    
    elseif isUnsafeHttpMethod() then

    elseif isBlackUA() then

    elseif isCC() then
    
    elseif isWhiteURL() then

	elseif isBlackURL() then

    elseif isEvilArgs() then
    
    elseif isEvilHeaders() then
    
    elseif isEvilReqBody() then
    
    elseif isEvilCookies() then
    
    end

end
