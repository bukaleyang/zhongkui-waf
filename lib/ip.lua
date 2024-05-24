-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local _M = {}

local bit = require "bit"
local lshift = bit.lshift
local band = bit.band
local pairs = pairs
local ipairs = ipairs
local type = type
local tonumber = tonumber
local find = string.find
local match = string.match
local ngxmatch = ngx.re.match

local insert = table.insert

local base = {23, 16, 8, 0}
local maskConst = 0xffffffff

function _M.getClientIP()
    local var = ngx.var
    local ips = {
        var.http_x_forwarded_for,
        var.http_proxy_client_ip,
        var.http_wl_proxy_client_ip,
        var.http_http_client_ip,
        var.http_http_x_forwarded_for,
        var.remote_addr
    }

    for _, ip in pairs(ips) do
        if ip and ip ~= "" then
            if type(ip) == "table" then
                ip = ip[1]
            end

            return ip
        end
    end

    return "unknown"
end

-- 是否内网IP
function _M.isPrivateIP(ip)
    if not ip then
        return false
    end

    if ip == '127.0.0.1' then
        return true
    end

    local m, err = ngxmatch(ip, '(\\d{1,3})\\.(\\d{1,3})\\.(?:\\d{1,3})\\.(?:\\d{1,3})', 'isjo')
    if m then
        local a, b = tonumber(m[1]), tonumber(m[2])
        if a == 10 then
            return true
        elseif a == 172 and b >= 16 and b <= 31 then
            return true
        elseif a == 192 and b == 168 then
            return true
        end
    end

    return false
end

function _M.ipToNumber(ip)
    if ip == nil or type(ip) ~= "string" then
        return 0
    end

    local number = 0
    local t = {}

    local _ = string.gsub(ip, "%d+",
        function(res)
            t[#t + 1] = res
        end
    )

    number = number + lshift(t[1], base[1]) * 2

    for i = 2, 4 do
        number = number + lshift(t[i], base[i])
    end

    return number
end

function _M.maskToNumber(mask)
    if mask == nil or type(mask) ~= "string" then
        return 0
    end

    local number = 0

    if find(mask, "%d%.") then
        number = _M.ipToNumber(mask)
    else
        if tonumber(mask) > 32 then
            return 0
        end
        number = maskConst - 2 ^ (32 - tonumber(mask)) + 1
    end

    return math.floor(number)
end

function _M.isSameSubnet(subnetTab, ip)
    local ipNumber = ngx.ctx.ipNumber
    if ipNumber == nil then
        ipNumber = _M.ipToNumber(ip)
        ngx.ctx.ipNumber = ipNumber
    end

    for value, maskNumber in pairs(subnetTab) do
        if band(ipNumber, maskNumber) == value then
            return true
        end
    end

    return false
end

-- ip黑白名单预处理，如果配置了网段，则计算网段的ip十进制数按位与掩码
function _M.initIpList(ipList)
    local result = {}
    local subnetTab = {}

    if not ipList or #ipList == 0 then
        return result
    end

    for _, v in ipairs(ipList) do
        local ip = match(v, "([%d%.]+)/?")
        local mask = match(v, "/([%d%.]+)")

        local ipNumber = _M.ipToNumber(ip)

        if mask then
            local maskNumber = _M.maskToNumber(mask)
            local res = band(ipNumber, maskNumber)

            subnetTab[res] = maskNumber
        else
            insert(result, ip)
        end
    end

    insert(result, subnetTab)

    return result
end

-- 把配置中混合在一起的单ip和ip网段区分开，{ip网段table},{ipList}
function _M.filterIPList(ipList)
    local t1, t2 = {}, {}

    if ipList and #ipList > 0 then
        for _, v in ipairs(ipList) do
            if find(v, '/') then
                insert(t1, v)
            else
                insert(t2, v)
            end
        end
    end

    t1 = _M.initIpList(t1)

    return t1, t2
end

return _M
