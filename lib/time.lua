-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local ngxmatch = ngx.re.match
local sub = string.sub
local tonumber = tonumber

local _M = {}

function _M.calculate_seconds_to_next_midnight()
    local localtime = ngx.localtime()

    local m, err = ngxmatch(localtime, "(\\d+):(\\d+):(\\d+)", "jo")
    if not m then
        ngx.log(ngx.ERR, "failed to calculate ttl ", err)
        return nil
    end

    return 86400 - tonumber(m[1]) * 3600 - tonumber(m[2]) * 60 - tonumber(m[3])
end

function _M.get_date_hour()
    local localtime = ngx.localtime()
    local hour = sub(localtime, 1, 13)
    return hour
end

function _M.get_hours()
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