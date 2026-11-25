-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2026 bukale bukale2022@163.com

-- 威胁情报名单解析：纯函数，不依赖 ngx，便于单独测试。
-- 上游格式差异较大（有的用 # 注释，有的用 ; 注释），
-- 这里统一按“行内第一个 # 或 ; 之后为注释”处理。

local _M = {}

local ipairs = ipairs
local tonumber = tonumber
local format = string.format
local lower = string.lower
local find = string.find
local sub = string.sub

local MAX_HEADER_LINES = 20

-- 不参与封禁的地址段：私网、回环、链路本地、CGNAT、文档/保留/组播等。
local RESERVED_CIDRS = {
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.31.196.0/24",
    "192.52.193.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "192.175.48.0/24",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
}

local function parse_ipv4(value)
    local a, b, c, d = value:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then
        return nil
    end

    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    if a > 255 or b > 255 or c > 255 or d > 255 then
        return nil
    end

    return a * 16777216 + b * 65536 + c * 256 + d
end

local function format_ipv4(n)
    return format("%d.%d.%d.%d",
        math.floor(n / 16777216) % 256,
        math.floor(n / 65536) % 256,
        math.floor(n / 256) % 256,
        n % 256)
end

local function cidr_range(cidr)
    local ip, prefix = cidr:match("^([^/]+)/(%d+)$")
    if not ip then
        ip, prefix = cidr, "32"
    end

    prefix = tonumber(prefix)
    local n = parse_ipv4(ip)
    if not n or not prefix or prefix < 0 or prefix > 32 then
        return nil
    end

    local size = 2 ^ (32 - prefix)
    local network = math.floor(n / size) * size
    return network, network + size - 1, prefix
end

local RESERVED_RANGES = {}
for _, cidr in ipairs(RESERVED_CIDRS) do
    local first, last = cidr_range(cidr)
    RESERVED_RANGES[#RESERVED_RANGES + 1] = {first, last}
end

local function is_reserved_range(first, last)
    for _, range in ipairs(RESERVED_RANGES) do
        if first <= range[2] and last >= range[1] then
            return true
        end
    end
    return false
end

-- 用于校验 DNS 解析结果，禁止情报源解析到内网/保留地址。
function _M.is_reserved_ip(ip)
    local n = parse_ipv4(ip)
    if not n then
        return true
    end

    for _, range in ipairs(RESERVED_RANGES) do
        if n >= range[1] and n <= range[2] then
            return true
        end
    end

    return false
end

-- 返回规范化 CIDR；非法、私网/保留段、前缀过短时返回 nil。
function _M.normalize_cidr(value, min_prefix)
    min_prefix = min_prefix or 8
    local first, last, prefix = cidr_range(value)
    if not first then
        return nil
    end
    if prefix < min_prefix then
        return nil
    end
    if is_reserved_range(first, last) then
        return nil
    end

    return format_ipv4(first) .. "/" .. prefix
end

-- 解析上游名单正文，返回 {cidr,...}, 统计信息, 上游文件头
function _M.parse_body(body, opts)
    opts = opts or {}
    local min_prefix = opts.minPrefix or 8

    local list = {}
    local seen = {}
    local header = {}
    local stats = {raw = 0, imported = 0, filtered = 0}

    if not body then
        return list, stats, header
    end

    for line in body:gmatch("[^\r\n]+") do
        local trimmed = line:match("^%s*(.-)%s*$")

        if trimmed ~= "" then
            local first = sub(trimmed, 1, 1)

            if first == "#" or first == ";" then
                -- 保留上游文件头：部分数据源要求保留版权/日期声明，也便于审计
                if #header < MAX_HEADER_LINES then
                    header[#header + 1] = trimmed
                end
            else
                stats.raw = stats.raw + 1

                local value = trimmed:gsub("[#;].*$", "")
                value = value:match("^%s*(.-)%s*$")
                local cidr = value ~= "" and _M.normalize_cidr(value, min_prefix) or nil

                if cidr then
                    if not seen[cidr] then
                        seen[cidr] = true
                        list[#list + 1] = cidr
                    else
                        stats.filtered = stats.filtered + 1
                    end
                else
                    stats.filtered = stats.filtered + 1
                end
            end
        end
    end

    stats.imported = #list
    return list, stats, header
end

function _M.parse_url(url)
    if type(url) ~= "string" then
        return nil
    end

    local scheme, rest = url:match("^(https?)://(.+)$")
    if not scheme or find(rest, "@", 1, true) then
        return nil
    end

    local hostport, path = rest:match("^([^/]+)(/.*)$")
    if not hostport then
        hostport, path = rest, "/"
    end

    local host, port = hostport:match("^([^:]+):(%d+)$")
    if not host then
        host, port = hostport, nil
    end

    port = tonumber(port) or (scheme == "https" and 443 or 80)

    return {
        scheme = scheme,
        host = host,
        port = port,
        path = path,
    }
end

-- 只允许 https 域名源，禁止 IP 字面量和本机域名，避免被配置成 SSRF 跳板。
function _M.source_allowed(url)
    local u = _M.parse_url(url)
    if not u or u.scheme ~= "https" or u.port ~= 443 then
        return false
    end

    local host = lower(u.host)
    if host == "localhost" or sub(host, -10) == ".localhost" then
        return false
    end
    if parse_ipv4(host) or not find(host, ".", 1, true) then
        return false
    end

    return true
end

_M.parse_ipv4 = parse_ipv4

return _M
