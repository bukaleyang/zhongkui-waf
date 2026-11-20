-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local stringutf8 = require "stringutf8"

local _M = {}

local ipairs = ipairs
local tonumber = tonumber
local find = string.find
local sub = string.sub
local ngxmatch = ngx.re.match

local trim = stringutf8.trim
local insert = table.insert

-- 客户端 IP 统一使用 nginx 的 $remote_addr：
--   * WAF 直接对外时，它就是真实客户端地址；
--   * 前面有 CDN/反向代理时，由 nginx realip 模块按可信代理配置还原。
-- 不直接采信客户端可自行伪造的 X-Forwarded-For / Proxy-Client-IP 等请求头，
-- 否则黑名单、CC、geoip 和攻击日志都会使用伪造值。
function _M.get_client_ip()
    return ngx.var.remote_addr or "unknown"
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

-- 解析IP名单：忽略空行，去掉每行中 # 及其后的注释内容（整行注释或行尾注释均可），再 trim
-- 返回 {ip1, ip2, ...}
function _M.parse_ip_lines(lines)
    local ip_list = {}

    if not lines then
        return ip_list
    end

    for _, line in ipairs(lines) do
        local ip = tostring(line)
        local comment_idx = find(ip, '#', 1, true)

        if comment_idx then
            ip = sub(ip, 1, comment_idx - 1)
        end

        ip = trim(ip) or ''

        if ip ~= '' then
            ip_list[#ip_list + 1] = ip
        end
    end

    return ip_list
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
