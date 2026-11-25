-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2026 bukale bukale2022@163.com

-- 威胁情报 IP 组自动更新：自行解析域名直连拉取，写独立数据文件，校验通过后只 reload 一次。

local cjson = require "cjson"
local config = require "config"
local file = require "file_utils"
local http = require "resty.http"
local dns = require "resty.dns.resolver"
local parser = require "lib.threat_intel_parser"
local ffi = require "ffi"

local IS_WINDOWS = ffi.os == "Windows"

local pairs = pairs
local ipairs = ipairs
local tonumber = tonumber
local tostring = tostring
local type = type
local pcall = pcall
local format = string.format
local concat = table.concat

local cjson_decode = cjson.decode
local cjson_encode = cjson.encode

local read_file = file.read_file_to_string
local write_file_atomic = file.write_string_to_file_atomic
local is_directory = file.is_directory
local mkdir = file.mkdir

local _M = {}

local IP_GROUP_PATH = config.CONF_PATH .. "/ipgroup.json"
local DATA_DIR = config.CONF_PATH .. "/ipgroup_data"
local LOCK_KEY = "threat_intel:refresh"
local LOCK_TTL = 600

local DEFAULT_SETTINGS = {
    enabled = true,
    hourUTC = 5,
    minuteUTC = 10,
    adminPort = 1226,
    connectTimeout = 5000,
    sendTimeout = 10000,
    readTimeout = 30000,
    maxBytes = 10 * 1024 * 1024,
    minEntries = 100,
    minPrefix = 8,
    shrinkRatio = 0.5,
    retryMinutes = 30,
    maxRedirects = 3,
}

local function clamp(value, min_value, max_value)
    if value < min_value then
        return min_value
    end
    if value > max_value then
        return max_value
    end
    return value
end

local function get_settings()
    local raw = config.get_system_config("threatIntel") or {}
    local settings = {}

    for k, v in pairs(DEFAULT_SETTINGS) do
        settings[k] = raw[k]
        if settings[k] == nil then
            settings[k] = v
        end
    end

    settings.enabled = settings.enabled ~= false and settings.enabled ~= "off"
    if raw.state == "off" then
        settings.enabled = false
    end
    settings.hourUTC = clamp(tonumber(settings.hourUTC) or 5, 0, 23)
    settings.minuteUTC = clamp(tonumber(settings.minuteUTC) or 10, 0, 59)
    settings.adminPort = clamp(tonumber(settings.adminPort) or 1226, 1, 65535)
    settings.connectTimeout = math.max(1000, tonumber(settings.connectTimeout) or 5000)
    settings.sendTimeout = math.max(1000, tonumber(settings.sendTimeout) or 10000)
    settings.readTimeout = math.max(1000, tonumber(settings.readTimeout) or 30000)
    settings.maxBytes = math.max(64 * 1024, tonumber(settings.maxBytes) or 10 * 1024 * 1024)
    settings.minEntries = math.max(1, tonumber(settings.minEntries) or 100)
    settings.minPrefix = clamp(tonumber(settings.minPrefix) or 8, 0, 32)
    settings.shrinkRatio = clamp(tonumber(settings.shrinkRatio) or 0.5, 0, 1)
    settings.retryMinutes = math.max(1, tonumber(settings.retryMinutes) or 30)
    settings.maxRedirects = clamp(tonumber(settings.maxRedirects) or 3, 0, 10)

    if type(raw.nameservers) == "table" and #raw.nameservers > 0 then
        settings.nameservers = raw.nameservers
    end

    return settings
end

local function read_groups()
    local json = read_file(IP_GROUP_PATH)
    if not json then
        return nil, "读取 ipgroup.json 失败"
    end

    local ok, result = pcall(cjson_decode, json)
    if not ok or type(result) ~= "table" then
        return nil, "ipgroup.json 格式错误"
    end

    if type(result.rules) ~= "table" then
        result.rules = {}
    end

    return result
end

local function write_groups(groups)
    local max_id = 0
    for _, g in ipairs(groups.rules) do
        local id = tonumber(g.id) or 0
        if id > max_id then
            max_id = id
        end
    end

    local next_id = tonumber(groups.nextId) or 1
    if next_id <= max_id then
        next_id = max_id + 1
    end
    groups.nextId = next_id

    return write_file_atomic(IP_GROUP_PATH, cjson_encode(groups))
end

local function find_group(groups, id)
    id = tonumber(id)
    if not id then
        return nil
    end

    for _, g in ipairs(groups.rules) do
        if tonumber(g.id) == id then
            return g
        end
    end
end

local function data_path(group)
    local rel = group.file
    if type(rel) == "string" and rel ~= ""
        and rel:sub(1, 1) ~= "/"
        and not rel:find("\\", 1, true)
        and not rel:find("..", 1, true) then
        return config.CONF_PATH .. "/" .. rel
    end

    return format("%s/%s.list", DATA_DIR, tostring(group.id))
end

local function ensure_data_dir()
    if not is_directory(DATA_DIR) then
        mkdir(DATA_DIR)
    end

    if not is_directory(DATA_DIR) then
        return nil, "创建威胁情报数据目录失败"
    end

    return true
end

-- 只读 /etc/resolv.conf，避免为了解析域名去改用户 nginx 的 resolver 指令。
local function system_nameservers()
    local servers = {}
    local f = io.open("/etc/resolv.conf", "r")
    if not f then
        return servers
    end

    for line in f:lines() do
        local ns = line:match("^%s*nameserver%s+([^%s#]+)")
        if ns and ns ~= "" then
            servers[#servers + 1] = ns
        end
    end

    f:close()
    return servers
end

local function resolve(host, settings)
    local literal = parser.parse_ipv4(host)
    if literal then
        return host
    end

    local nameservers = settings.nameservers
    if type(nameservers) ~= "table" or #nameservers == 0 then
        nameservers = system_nameservers()
    end
    if #nameservers == 0 then
        if IS_WINDOWS then
            return nil, '未找到可用的 DNS 服务器：Windows 无 /etc/resolv.conf，'
                .. '请在 conf/system.json 的 threatIntel.nameservers 中配置，'
                .. '如 ["223.5.5.5","119.29.29.29"]'
        end
        return nil, "未找到可用的 DNS 服务器：请检查 /etc/resolv.conf 的 nameserver，"
            .. "或在 conf/system.json 的 threatIntel.nameservers 中配置"
    end

    local r, err = dns:new({
        nameservers = nameservers,
        timeout = 2000,
        -- retrans 是总尝试次数，按 DNS 个数才能真正轮到备用服务器
        retrans = #nameservers,
    })
    if not r then
        return nil, "DNS 初始化失败: " .. tostring(err)
    end

    local answers, err = r:query(host, {qtype = dns.TYPE_A})
    if not answers then
        return nil, "DNS 解析失败: " .. tostring(err)
    end
    if answers.errcode then
        return nil, "DNS 解析失败: " .. tostring(answers.errstr or answers.errcode)
    end

    for _, ans in ipairs(answers) do
        if ans.type == dns.TYPE_A and ans.address then
            return ans.address
        end
    end

    return nil, "未找到 A 记录"
end

local function read_limited(res, max_bytes)
    local reader = res.body_reader
    if not reader then
        return nil, "响应没有正文"
    end

    local chunks = {}
    local total = 0

    while true do
        local chunk, err = reader(65536)

        if err then
            if err ~= "closed" then
                return nil, "读取响应失败: " .. tostring(err)
            end

            if chunk then
                total = total + #chunk
                if total > max_bytes then
                    return nil, "响应超过大小限制"
                end
                chunks[#chunks + 1] = chunk
            end
            break
        end

        if not chunk then
            break
        end

        total = total + #chunk
        if total > max_bytes then
            return nil, "响应超过大小限制"
        end

        chunks[#chunks + 1] = chunk
    end

    return concat(chunks)
end

local function absolute_url(u, location)
    if location:match("^https?://") then
        return location
    end

    if location:sub(1, 2) == "//" then
        return u.scheme .. ":" .. location
    end

    local authority = u.host
    if u.port ~= 443 then
        authority = authority .. ":" .. tostring(u.port)
    end

    if location:sub(1, 1) == "/" then
        return u.scheme .. "://" .. authority .. location
    end

    local base = u.path:match("^(.*/)") or "/"
    return u.scheme .. "://" .. authority .. base .. location
end

local function fetch_url(url, headers, settings, depth)
    depth = depth or 0
    if depth > settings.maxRedirects then
        return nil, "重定向次数过多"
    end
    if not parser.source_allowed(url) then
        return nil, "数据源地址不允许: " .. tostring(url)
    end

    local u = parser.parse_url(url)
    if not u then
        return nil, "数据源地址格式错误"
    end

    local ip, err = resolve(u.host, settings)
    if not ip then
        return nil, err
    end
    if parser.is_reserved_ip(ip) then
        return nil, "数据源解析到内网地址: " .. tostring(ip)
    end

    local httpc, err = http.new()
    if not httpc then
        return nil, tostring(err)
    end
    httpc:set_timeouts(settings.connectTimeout, settings.sendTimeout, settings.readTimeout)

    local ok, connect_err = httpc:connect({
        scheme = u.scheme,
        host = ip,
        port = u.port,
        ssl_server_name = u.host,
        ssl_verify = true,
    })
    if not ok then
        httpc:close()
        return nil, "连接 " .. u.host .. " 失败: " .. tostring(connect_err)
    end

    local host_header = u.host
    if u.port ~= 443 then
        host_header = host_header .. ":" .. tostring(u.port)
    end

    local req_headers = {
        Host = host_header,
        ["User-Agent"] = "ZhongKui-WAF/1.0",
        ["Accept"] = "text/plain, */*",
        ["Connection"] = "close",
    }
    for k, v in pairs(headers or {}) do
        req_headers[k] = v
    end

    local res, request_err = httpc:request({
        method = "GET",
        path = u.path,
        headers = req_headers,
    })
    if not res then
        httpc:close()
        return nil, "请求失败: " .. tostring(request_err)
    end

    if res.status == 301 or res.status == 302 or res.status == 303
        or res.status == 307 or res.status == 308 then
        local location = res.headers["Location"]
        httpc:close()

        if not location or location == "" then
            return nil, "重定向缺少 Location"
        end

        local target = absolute_url(u, location)
        local tu = parser.parse_url(target)
        -- 跨主机重定向时不能复用条件请求头，否则可能拿到错误的 304
        local next_headers = (tu and tu.host == u.host) and headers or {}

        return fetch_url(target, next_headers, settings, depth + 1)
    end

    if res.status == 304 then
        httpc:close()
        return {status = 304}
    end

    if res.status ~= 200 then
        httpc:close()
        return nil, "上游返回 HTTP " .. tostring(res.status)
    end

    local body, read_err = read_limited(res, settings.maxBytes)
    httpc:close()
    if not body then
        return nil, read_err
    end

    return {
        status = 200,
        body = body,
        etag = res.headers["ETag"],
        lastModified = res.headers["Last-Modified"],
    }
end

-- 统一存 UTC，页面展示时由前端转本地时间
local function now_string()
    return os.date("!%Y-%m-%dT%H:%M:%SZ")
end

local function build_file_content(group, list, stats, header, fetched_at, etag, last_modified)
    local lines = {
        "# source: " .. tostring(group.sourceUrl),
        "# source_name: " .. tostring(group.sourceName or ""),
        "# fetched_at: " .. fetched_at,
        "# etag: " .. tostring(etag or ""),
        "# last_modified: " .. tostring(last_modified or ""),
        "# raw_entries: " .. tostring(stats.raw),
        "# imported_entries: " .. tostring(stats.imported),
        "# filtered_entries: " .. tostring(stats.filtered),
    }

    if #header > 0 then
        lines[#lines + 1] = "# upstream_header:"
        for _, h in ipairs(header) do
            lines[#lines + 1] = "#   " .. h
        end
    end

    lines[#lines + 1] = ""
    for _, cidr in ipairs(list) do
        lines[#lines + 1] = cidr
    end

    return concat(lines, "\n") .. "\n"
end

-- 本地数据文件是否仍与元数据一致：文件丢失、被截断或被手工改动都需要重新落盘
local function local_data_intact(group, settings)
    if not group.contentHash then
        return false
    end

    local content = read_file(data_path(group))
    if not content then
        return false
    end

    local list = parser.parse_body(content, {minPrefix = settings.minPrefix})
    return ngx.md5(concat(list, "\n")) == group.contentHash
end

local function fetch_group(group, settings)
    local intact = local_data_intact(group, settings)

    -- 本地文件不可用时不能发条件请求，否则上游 304 会让名单永远补不回来
    local headers = {}
    if intact then
        if group.etag and group.etag ~= "" then
            headers["If-None-Match"] = group.etag
        end
        if group.lastModified and group.lastModified ~= "" then
            headers["If-Modified-Since"] = group.lastModified
        end
    end

    local result, err = fetch_url(group.sourceUrl, headers, settings)
    local now = now_string()

    group.lastCheck = now

    if not result then
        group.lastStatus = "error"
        group.lastError = tostring(err)
        return false, err
    end

    group.lastError = nil

    if result.status == 304 then
        if not intact then
            group.lastStatus = "error"
            group.lastError = "本地数据文件不可用，但上游返回 304"
            return false, group.lastError
        end

        group.lastStatus = "not_modified"
        return true, nil, false
    end

    local body = result.body or ""
    local head = body:sub(1, 256):lower()
    if head:find("<!doctype", 1, true) or head:find("<html", 1, true) then
        group.lastStatus = "error"
        group.lastError = "上游返回 HTML 页面"
        return false, group.lastError
    end

    local list, stats, header = parser.parse_body(body, {minPrefix = settings.minPrefix})

    if stats.imported < settings.minEntries then
        group.lastStatus = "error"
        group.lastError = format("有效条目过少: %d < %d", stats.imported, settings.minEntries)
        return false, group.lastError
    end

    local previous = tonumber(group.ipCount) or 0
    if not settings.force and previous > 0
        and stats.imported < previous * settings.shrinkRatio then
        group.lastStatus = "error"
        group.lastError = format("条目数异常减少: %d -> %d", previous, stats.imported)
        return false, group.lastError
    end

    local content_hash = ngx.md5(concat(list, "\n"))
    if intact and group.contentHash == content_hash then
        group.lastStatus = "unchanged"
        group.etag = result.etag or group.etag
        group.lastModified = result.lastModified or group.lastModified
        return true, nil, false
    end

    local path = data_path(group)
    local content = build_file_content(group, list, stats, header, now, result.etag, result.lastModified)
    local ok, write_err = write_file_atomic(path, content)
    if not ok then
        group.lastStatus = "error"
        group.lastError = "写入数据文件失败: " .. tostring(write_err)
        return false, group.lastError
    end

    -- data_path 对非法 file 会回退到 conf/ipgroup_data，此时必须回填真实相对路径，
    -- 否则 config.resolve_ip_group_file 会拒绝该路径，reload 后本组名单不生效
    if type(group.file) ~= "string" or group.file == ""
        or (config.CONF_PATH .. "/" .. group.file) ~= path then
        group.file = "ipgroup_data/" .. tostring(group.id) .. ".list"
    end
    group.ipCount = stats.imported
    group.filteredCount = stats.filtered
    group.rawCount = stats.raw
    group.lastUpdate = now
    group.lastStatus = "updated"
    group.etag = result.etag
    group.lastModified = result.lastModified
    group.contentHash = content_hash
    group.pendingReload = true

    return true, nil, true
end

local function new_lock_token()
    return format("%s:%d",
        tostring(ngx.worker.pid()),
        math.floor((ngx.now() or os.time()) * 1000))
end

local function acquire_lock()
    local dict = ngx.shared.dict_locks
    local token = new_lock_token()

    if not dict then
        return token
    end

    if dict:add(LOCK_KEY, token, LOCK_TTL) ~= true then
        return nil
    end

    return token
end

local function release_lock(token)
    local dict = ngx.shared.dict_locks
    if dict and token and dict:get(LOCK_KEY) == token then
        dict:delete(LOCK_KEY)
    end
end

-- 立即更新指定的源；id 为空时更新所有带 sourceUrl 的 IP 组。
function _M.refresh(opts)
    opts = opts or {}
    local settings = get_settings()
    settings.force = opts.force == true

    local groups, err = read_groups()
    if not groups then
        return {code = 500, data = {}, msg = err}
    end

    local targets = {}
    if opts.id then
        local g = find_group(groups, opts.id)
        if not g then
            return {code = 404, data = {}, msg = "IP组不存在"}
        end
        if not g.sourceUrl then
            return {code = 400, data = {}, msg = "该IP组不是威胁情报组"}
        end
        targets[1] = g
    else
        for _, g in ipairs(groups.rules) do
            if g.sourceUrl and g.autoUpdate ~= false then
                targets[#targets + 1] = g
            end
        end
    end

    if #targets == 0 then
        return {code = 400, data = {}, msg = "没有可更新的威胁情报组"}
    end

    local lock_token = acquire_lock()
    if not lock_token then
        return {code = 429, data = {}, msg = "更新任务正在执行，请稍后重试"}
    end

    local ok, dir_err = ensure_data_dir()
    if not ok then
        release_lock(lock_token)
        return {code = 500, data = {}, msg = dir_err}
    end

    local results = {}
    local changed = 0
    local failed = 0
    local first_error
    local need_reload = false

    for _, g in ipairs(targets) do
        -- pcall 会把 fetch_group 的返回值整体后移一位
        local called, ok, _, did_change = pcall(fetch_group, g, settings)

        if not called then
            g.lastStatus = "error"
            g.lastError = tostring(ok)
            failed = failed + 1
        elseif not ok then
            failed = failed + 1
        elseif did_change then
            changed = changed + 1
        end

        if failed > 0 and not first_error then
            first_error = g.lastError
        end

        if g.pendingReload then
            need_reload = true
        end

        results[#results + 1] = {
            id = g.id,
            groupName = g.groupName,
            status = g.lastStatus,
            ipCount = g.ipCount or 0,
            filteredCount = g.filteredCount or 0,
            message = g.lastError or "",
        }
    end

    local saved, save_err = write_groups(groups)
    if not saved then
        release_lock(lock_token)
        return {code = 500, data = {groups = results}, msg = "保存元数据失败: " .. tostring(save_err)}
    end

    local reloaded = true
    local reload_err

    if need_reload then
        local called, result, called_err = pcall(config.reload_config_file)
        if not called then
            reloaded = false
            reload_err = tostring(result)
        else
            reloaded = result ~= false
            reload_err = called_err
        end

        for _, g in ipairs(targets) do
            if reloaded then
                g.pendingReload = nil
            elseif g.lastStatus == "updated" then
                g.pendingReload = true
            end
        end

        write_groups(groups)
    end

    release_lock(lock_token)

    local msg
    if failed == #targets then
        msg = "更新失败：" .. tostring(first_error or "未知错误")
    elseif failed > 0 then
        msg = format("成功 %d 个，失败 %d 个：%s", #targets - failed, failed, tostring(first_error or "未知错误"))
    elseif changed == 0 then
        msg = "已是最新版"
    elseif opts.id then
        msg = "已更新"
    else
        msg = format("已更新 %d 个IP组", changed)
    end

    if not reloaded then
        msg = "名单已写入，但 nginx 重载失败: " .. tostring(reload_err)
        if failed > 0 then
            msg = msg .. format("（%d 个数据源更新失败）", failed)
        end
    end

    return {
        code = (failed == #targets or not reloaded) and 500 or 200,
        data = {
            groups = results,
            changed = changed,
            failed = failed,
            reloaded = reloaded,
        },
        msg = msg,
    }
end

function _M.refresh_due()
    local settings = get_settings()
    if not settings.enabled then
        return {code = 200, data = {skipped = true}, msg = "威胁情报自动更新已关闭"}
    end

    return _M.refresh()
end

-- 本机 admin 接口只做一次普通 HTTP 请求，HTTPS 拉取在 admin server 上下文中执行。
local function request_refresh_due(settings)
    local httpc, err = http.new()
    if not httpc then
        return nil, tostring(err)
    end
    httpc:set_timeouts(3000, 3000, 120000)

    local ok, connect_err = httpc:connect({
        scheme = "http",
        host = "127.0.0.1",
        port = settings.adminPort,
    })
    if not ok then
        httpc:close()
        return nil, "连接本机管理端口失败: " .. tostring(connect_err)
    end

    local res, request_err = httpc:request({
        method = "GET",
        path = "/common/ipgroups/refresh-due",
        headers = {
            Host = "127.0.0.1:" .. tostring(settings.adminPort),
            ["Connection"] = "close",
        },
    })
    if not res then
        httpc:close()
        return nil, "请求本机管理接口失败: " .. tostring(request_err)
    end

    local body, read_err = read_limited(res, 1024 * 1024)
    httpc:close()
    if not body then
        return nil, read_err
    end

    return body
end

-- 把 UTC 时间转换成 epoch，避免 os.time 按本地时区解释。
local function utc_to_epoch(t)
    local y, m, d = t.year, t.month, t.day
    if m <= 2 then
        y = y - 1
        m = m + 12
    end

    local era = math.floor(y / 400)
    local yoe = y - era * 400
    local doy = math.floor((153 * (m - 3) + 2) / 5) + d - 1
    local doe = yoe * 365 + math.floor(yoe / 4) - math.floor(yoe / 100) + doy
    local days = era * 146097 + doe - 719468

    return days * 86400 + t.hour * 3600 + t.min * 60
end

local function seconds_until_next(hour, minute)
    local now = os.time()
    local now_utc = os.date("!*t", now)
    local target_epoch = utc_to_epoch({
        year = now_utc.year,
        month = now_utc.month,
        day = now_utc.day,
        hour = hour,
        min = minute,
    })

    if target_epoch <= now then
        target_epoch = target_epoch + 86400
    end

    return target_epoch - now
end

local retry_count = 0

local function schedule_next(settings)
    local delay = seconds_until_next(settings.hourUTC, settings.minuteUTC)
    local ok, err = ngx.timer.at(delay, function(premature)
        _M._timer_handler(premature)
    end)
    if not ok then
        ngx.log(ngx.ERR, "failed to schedule threat intel timer: ", err)
    end
end

function _M._timer_handler(premature)
    if premature then
        return
    end

    local settings = get_settings()
    if not settings.enabled then
        return
    end

    local body, err = request_refresh_due(settings)
    local ok, result = false, nil

    if body then
        ok, result = pcall(cjson_decode, body)
    end

    if ok and type(result) == "table" and result.code == 200 then
        local data = result.data or {}
        local failed = tonumber(data.failed or 0) or 0

        if failed == 0 and data.reloaded ~= false then
            retry_count = 0
            ngx.log(ngx.INFO, "threat intel refresh: ", body)
            schedule_next(settings)
            return
        end
        if data.reloaded == false then
            err = "nginx 重载失败"
        else
            err = format("%d 个数据源更新失败", failed)
        end
    end

    ngx.log(ngx.ERR, "threat intel refresh failed: ", tostring(err or body))

    retry_count = retry_count + 1
    if retry_count <= 3 then
        local scheduled, schedule_err = ngx.timer.at(settings.retryMinutes * 60, function(p)
            _M._timer_handler(p)
        end)
        if not scheduled then
            ngx.log(ngx.ERR, "failed to schedule threat intel retry: ", schedule_err)
        end
        return
    end

    retry_count = 0
    schedule_next(settings)
end

function _M.start_auto_refresh()
    if ngx.worker.id() ~= 0 then
        return
    end

    local settings = get_settings()
    if not settings.enabled then
        ngx.log(ngx.INFO, "threat intel auto refresh disabled")
        return
    end

    -- 首次启动或上次失败时尽快拉取一次，之后按每天固定 UTC 时间执行。
    local groups = read_groups()
    local pending = false
    local has_managed = false

    if groups then
        for _, g in ipairs(groups.rules) do
            if g.sourceUrl and g.autoUpdate ~= false then
                has_managed = true
                local status = g.lastStatus
                -- 数据已落盘但 reload 失败时也要尽快补一次，否则新名单要等到次日
                if g.pendingReload
                    or not status or status == "" or status == "never" or status == "error" then
                    pending = true
                    break
                end
            end
        end
    end

    -- 老版本升级后 ipgroup.json 里可能还没有威胁情报组，此时不启动定时器
    if not has_managed then
        ngx.log(ngx.INFO, "no threat intel ip group configured, auto refresh skipped")
        return
    end

    if pending then
        local ok, err = ngx.timer.at(60, function(premature)
            _M._timer_handler(premature)
        end)
        if not ok then
            ngx.log(ngx.ERR, "failed to create initial threat intel timer: ", err)
        end
        return
    end

    schedule_next(settings)
end

return _M
