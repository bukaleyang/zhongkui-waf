local sub = string.sub
local tonumber = tonumber

local _M = {}

function _M.getExpireTime()
    local localtime = ngx.localtime()
    local hour = sub(localtime, 12, 13)
    local expireTime = (24 - tonumber(hour)) * 3600
    return expireTime
end

function _M.getDateHour()
    local localtime = ngx.localtime()
    local hour = sub(localtime, 1, 13)
    return hour
end

function _M.getHours()
    local hours = {}
    local today = ngx.today()
    local hour = nil
    for i = 0, 23 do
        if i < 10 then
            hour = today .. ' 0' .. i
        else
            hour = today .. ' ' .. i
        end
        hours[i + 1] = hour
    end

    return hours
end

return _M