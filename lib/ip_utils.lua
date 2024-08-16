-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local _M = {}

local stringutf8 = require "stringutf8"

local pairs = pairs
local ipairs = ipairs
local tonumber = tonumber
local find = string.find
local sub = string.sub
local trim = stringutf8.trim
local ngxmatch = ngx.re.match

local insert = table.insert

function _M.get_client_ip()
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
        if ip and #ip > 0 then
            local idx = find(ip, ",")
            if idx and idx > 0 then
                ip = sub(ip, 1, idx - 1)
            end

            return trim(ip)
        end
    end

    return "unknown"
end

-- 是否内网IP
function _M.is_private_ip(ip)
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
    else
        if err then
            ngx.log(ngx.ERR, "error: ", err)
            return
        end
    end

    return false
end

-- 把配置中混合在一起的单ip和ip网段区分开，{ip网段table},{ips}
function _M.filter_ip_list(ips)
    local t1, t2 = {}, {}

    if ips and #ips > 0 then
        for _, v in ipairs(ips) do
            if find(v, '/') then
                insert(t1, v)
            else
                insert(t2, v)
            end
        end
    end

    return t1, t2
end

return _M
