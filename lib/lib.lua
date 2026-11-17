-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local config = require "config"
local redis_cli = require "redis_cli"
local decoder = require "decoder"
local action = require "action"
local captcha = require "captcha"
local request = require "request"
local upload = require "upload"
local http_method = require "http_method"
local ck = require "resty.cookie"
local libinjection = require "resty.libinjection"
local nkeys = require "table.nkeys"
local constants = require "constants"
local file_utils = require "file_utils"

local block_ip = action.block_ip
local do_action = action.do_action
local ipairs, pairs = ipairs, pairs
local type = type
local tonumber = tonumber

local lower = string.lower
local upper = string.upper
local sub = string.sub
local byte = string.byte
local find = string.find
local match = string.match
local gsub = string.gsub
local gmatch = string.gmatch
local unescape_uri = decoder.unescape_uri
local get_request_body = request.get_request_body
local get_boundary = request.get_boundary
local get_content_type = request.get_content_type

local concat = table.concat
local ngxfind = ngx.re.find
local md5 = ngx.md5

local is_system_option_on = config.is_system_option_on
local is_site_option_on = config.is_site_option_on
local get_site_config = config.get_site_config
local get_site_security_modules = config.get_site_security_modules
local get_system_config = config.get_system_config
local read_file_to_table = file_utils.read_file_to_table

local _M = {}

-- 超大请求体保护阈值
-- raw body 超过该值后按表单 part 逐个做 libinjection，
-- 避免大请求把 worker 长时间占死（见 is_evil_request_body）
local MAX_BODY_INSPECT_LEN = 1024 * 1024
-- Content-Type 缺失/重复/歧义时，超过该长度的 body 无法可靠嗅探 multipart，
-- 且这种请求本身不合规，fileExt 开启时直接 fail-closed
local MAX_UNKNOWN_CT_SNIFF_LEN = 1024 * 1024
-- 二进制内容中可打印片段的最小长度，过短片段噪声太大
local MIN_PRINTABLE_RUN = 6
-- 单个上传文件内容检查上限：只检查文件前 256KB，其余丢弃，
-- 否则逐行累积 + 全量规则匹配会让 CPU 随文件体积线性/平方增长
local MAX_FILE_CONTENT_LEN = 256 * 1024

-- whether or not the regular expression matches on the input
local function matches(input, regex, options, ctx, nth)
    if not options then
        options = "isjo"
    end

    if not nth then
        nth = 0
    end

    return ngxfind(input, regex, options, ctx, nth)
end


local function match_rule(rule_table, str, options)
    if str == nil or next(rule_table) == nil then
        return false
    end

    for _, t in ipairs(rule_table) do
        if matches(str, t.rule, options) then
            return true, t
        end
    end

    return false
end

local function is_group_match(group, ip)
    local matcher = config.ipgroups[group]
    if matcher then
        return matcher:match(ip)
    end

    return false
end

function _M.is_white_ip()
    if is_site_option_on("whiteIP") then
        local ip = ngx.ctx.ip
        if ip == "unknown" then
            return false
        end

        --local module = get_site_security_modules("whiteIp")
        if is_group_match(constants.KEY_IP_GROUPS_WHITELIST, ip) then
            -- do_action(module.moduleName, module.rules[1])
            ngx.status = ngx.OK
            return ngx.exit(ngx.status)
        end
    end
end

-- Returns true if the client ip is in the blackList,otherwise false
function _M.is_black_ip()
    if is_site_option_on("blackIP") then
        local ip = ngx.ctx.ip
        if ip == "unknown" then
            return false
        end

        local exists = nil

        if ngx.ctx.geoip.is_allowed == false then
            exists = true
        else
            if is_system_option_on("redis") then
                exists = redis_cli.get(constants.KEY_BLACKIP_PREFIX .. ip)
            else
                local blackip = ngx.shared.dict_blackip
                exists = blackip:get(ip)
            end
        end

        if not exists then
            if is_group_match(constants.KEY_IP_GROUPS_BLACKLIST, ip) then
                exists = true
            end
        end

        if exists then
            local module = get_site_security_modules("blackIp")
            do_action(module.moduleName, module.rules[1])
        end
    end
end

function _M.is_unsafe_http_method()
    if not is_site_option_on("httpMethod") then
        return
    end

    local module = get_site_security_modules("httpMethod")
    local allowed = http_method.build_allowed(module and module.rules or {})

    -- 允许列表为空会拦截所有请求（含管理后台），此时放行并记录错误
    if next(allowed) == nil then
        ngx.log(ngx.ERR, "httpMethod is on but no allowed method configured")
        return
    end

    local method_name = upper(ngx.req.get_method() or "")
    if http_method.is_allowed(method_name, allowed) then
        return
    end

    -- 方法名可能包含非方法字符，写日志前只保留方法字符
    local label = gsub(method_name, "[^A-Z0-9_-]", "?")
    if label == "" then
        label = "UNKNOWN"
    end

    -- 白名单规则的动作固定为 allow，拦截需要独立的规则表
    local rule_table = {
        rule = "method_not_allowed:" .. sub(label, 1, 32),
        attackType = "unsafe_method",
        action = "redirect",
        severityLevel = "high"
    }

    do_action(module.moduleName, rule_table, label)
end

function _M.is_bot()
    if is_site_option_on("bot") then
        captcha.check_captcha()

        local ip = ngx.ctx.ip
        local trap = get_site_config("bot").trap
        if trap.state == "on" then
            local ruri = ngx.var.request_uri
            local uri = ngx.var.uri

            if uri == trap.uri or ruri == trap.uri then
                local module = get_site_security_modules("botTrap")
                local rule_table = module.rules[1]
                block_ip(ip, rule_table)
                do_action(module.moduleName, rule_table)
                return true
            end
        end

        local ua = ngx.ctx.ua

        local module = get_site_security_modules("user-agent")

        -- 白名单优先：action=allow 的 UA 规则（搜索引擎爬虫）必须先判定。
        -- 规则数组会被 rulesSort 按命中热度重排，不能依赖“白名单排在黑名单前面”；
        -- 一旦 deny 规则先命中就已经 block_ip，白名单再匹配也来不及。
        if ua and ua ~= "" then
            for _, t in ipairs(module.rules) do
                if upper(t.action or "") == "ALLOW" and matches(ua, t.rule) then
                    -- 命中即跳过 Bot 检测：不 block_ip（正常爬虫不该进黑名单），
                    -- 也不 do_action（allow 会直接放行整个请求，跳过后续 SQLi/XSS/CC 检测）
                    return false
                end
            end
        end

        local m, rule_table = match_rule(module.rules, ua)
        if m then
            block_ip(ip, rule_table)
            do_action(module.moduleName, rule_table)
            return true
        end
    end
end

function _M.is_cc()
    if is_site_option_on("cc") then
        local ip = ngx.ctx.ip

        local module = get_site_security_modules("cc")
        local rules = module.rules
        for _, rule_table in pairs(rules) do
            local countType = lower(rule_table.countType)
            local pattern = rule_table.pattern
            local match = true
            local matchData = nil
            local key = ""
            if countType == "url" then
                local url = ngx.var.uri
                key = ip .. md5(url)
                matchData = url
            elseif countType == "ip" then
                key = ip
                matchData = ip
            end

            if pattern and pattern ~= "" then
                if not matches(matchData, pattern) then
                    match = false
                else
                    key = ip .. md5(pattern)
                end
            end

            if match then
                if is_system_option_on("redis") then
                    key = "cc_req_count:" .. key
                    local count, _ = redis_cli.incr(key, rule_table.duration)
                    if not count then
                        redis_cli.set(key, 1, rule_table.duration)
                    elseif count >= rule_table.threshold then
                        ngx.ctx.is_cc = true
                        block_ip(ip, rule_table)
                        do_action(module.moduleName, rule_table, nil, rule_table.rule, 403)

                        return true
                    end
                else
                    local limit = ngx.shared.dict_cclimit
                    local count, _ = limit:incr(key, 1, 0, rule_table.duration)
                    if not count then
                        limit:set(key, 1, rule_table.duration)
                    elseif count >= rule_table.threshold then
                        ngx.ctx.is_cc = true
                        block_ip(ip, rule_table)
                        do_action(module.moduleName, rule_table, nil, rule_table.rule, 403)

                        return true
                    end
                end
            end
        end
    end
end

function _M.is_acl()
    if is_site_option_on("acl") then
        local module = get_site_security_modules("acl")
        local rules = module.rules
        if rules == nil or nkeys(rules) == 0 then
            return false
        end

        for _, rule_table in pairs(rules) do
            local conditions = rule_table.conditions
            local match = true
            for _, condition in pairs(conditions) do
                local field = condition.field
                local field_name = condition.name
                local pattern = condition.pattern
                local match_value = ''
                if field == 'URL' then
                    match_value = ngx.var.request_uri
                elseif field == 'Cookie' then
                    if field_name ~= nil and field_name ~= '' then
                        local cookies = ck:new()
                        if not cookies then
                            match = false
                            break
                        else
                            match_value = cookies:get(field_name)
                        end
                    else
                        match_value = ngx.var.http_cookie
                    end
                elseif field == 'Header' then
                    local headers = ngx.req.get_headers()
                    if headers then
                        if field_name ~= nil and field_name ~= '' then
                            match_value = headers[field_name]
                        else
                            match_value = concat(headers, '')
                        end
                    else
                        match = false
                        break
                    end
                elseif field == 'Referer' then
                    match_value = ngx.var.http_referer
                elseif field == 'User-Agent' then
                    match_value = ngx.var.http_user_agent
                elseif field == 'IP' then
                    local ip = ngx.ctx.ip
                    local operator = condition.operator
                    local ipGroupId = condition.ipGroupId
                    if operator == 'in' then
                        if is_group_match(ipGroupId, ip) == false then
                            match = false
                            break
                        end
                    elseif operator == 'notin' then
                        if is_group_match(ipGroupId, ip) then
                            match = false
                            break
                        end
                    elseif operator == 'equal' then
                        match_value = ip
                    end
                end

                if pattern == '' then
                    if match_value ~= nil and match_value ~= '' then
                        match = false
                        break
                    end
                else
                    if not matches(match_value, pattern) then
                        match = false
                        break
                    end
                end
            end

            if match then
                local ip = ngx.ctx.ip
                block_ip(ip, rule_table)
                do_action(module.moduleName, rule_table)
                return true
            end
        end
    end
end

-- Returns true if the whiteURL rule is matched, otherwise false
function _M.is_white_url()
    if is_site_option_on("whiteUrl") then
        local url = ngx.var.uri
        if url == nil or url == "" then
            return false
        end
        local module = get_site_security_modules("whiteUrl")
        local m, rule_table = match_rule(module.rules, url)
        if m then
            do_action(module.moduleName, rule_table)
            return true
        end
        return false
    end
end

-- Returns true if the url rule is matched, otherwise false
function _M.is_black_url()
    if is_site_option_on("blackUrl") then
        local url = ngx.var.uri
        if url == nil or url == "" then
            return false
        end

        local module = get_site_security_modules("blackUrl")
        local m, rule_table = match_rule(module.rules, url)
        if m then
            do_action(module.moduleName, rule_table)
            return true
        end
    end
    return false
end

function _M.is_evil_args()
    if is_site_option_on("args") then
        local args = ngx.req.get_uri_args()
        if args then
            for _, val in pairs(args) do
                local vals = val
                if type(val) == "table" then
                    vals = concat(val, ", ")
                end

                if vals and type(vals) ~= "boolean" and vals ~= "" then
                    vals = unescape_uri(vals)
                    local module = get_site_security_modules("args")
                    local m, rule_table = match_rule(module.rules, vals)
                    if m then
                        do_action(module.moduleName, rule_table)
                        return true
                    end
                    _M.is_sqli_or_xss(vals)
                end
            end
        end
    end
end

function _M.is_evil_headers()
    if is_site_option_on("headers") then
        local module = get_site_security_modules("headers")
        local headers = ngx.req.get_headers() or {}

        -- 遍历全部请求头，覆盖自定义头与转发头中的 payload。
        -- Cookie 交给 cookie 模块单独检测，避免重复匹配和攻击类型归属混乱。
        for name, value in pairs(headers) do
            if name ~= "cookie" then
                if type(value) == "table" then
                    for _, item in ipairs(value) do
                        if item and item ~= "" then
                            local m, rule_table = match_rule(module.rules, item)
                            if m then
                                do_action(module.moduleName, rule_table, name .. ": " .. sub(item, 1, 512))
                                return true
                            end
                        end
                    end
                elseif type(value) == "string" and value ~= "" then
                    local m, rule_table = match_rule(module.rules, value)
                    if m then
                        do_action(module.moduleName, rule_table, name .. ": " .. sub(value, 1, 512))
                        return true
                    end
                end
            end
        end
    end
end

-- 上传拦截日志只保留必要上下文，避免整段 body/文件内容写日志
local MAX_UPLOAD_LOG_LEN = 2048

local function sanitize_log_data(data)
    if type(data) ~= "string" then
        return data
    end

    local s = gsub(data, "[\r\n]+", " ")
    if #s > MAX_UPLOAD_LOG_LEN then
        s = sub(s, 1, MAX_UPLOAD_LOG_LEN) .. "...[truncated]"
    end

    return s
end

-- 上传文件类型白名单判定：返回 true 表示应当拦截
-- fileExt 是白名单模块：state=on 的规则表示“允许的类型”，所以拦截时
-- 不能复用白名单规则（其 action=allow），必须构造独立的拦截规则表。
local function do_upload_block(reason, line)
    local module = get_site_security_modules("fileExt")
    local module_name = module and module.moduleName or "fileExt"

    local rule_table = {
        rule = "upload_ext:" .. sub(reason, 1, 64),
        attackType = "file_ext",
        action = "redirect",
        severityLevel = "high"
    }

    local data = sanitize_log_data(line)
    local attack_log = get_system_config("attackLog")
    -- system.json 的 jsonFormat 取值为字符串 on/off
    if is_system_option_on("attackLog") and attack_log and attack_log.jsonFormat ~= "on" then
        data = "[" .. tostring(data) .. "]"
    end

    do_action(module_name, rule_table, data)

    return true
end

function _M.is_evil_file_ext(file_name, line)
    if not is_site_option_on("fileExt") then
        return false
    end

    -- filename="" 表示浏览器未选择文件，交给后续内容检查
    if file_name == nil or file_name == '' then
        return false
    end

    local module = get_site_security_modules("fileExt")
    if not module then
        -- 配置缺失时不直接报错，按未知类型拦截
        return do_upload_block("module_missing", line)
    end

    local allowed = upload.build_allowed(module.rules)
    local ok, reason = upload.check_filename(file_name, allowed)
    if ok then
        return false
    end

    return do_upload_block(reason, line)
end

function _M.is_evil_file(body)
    local module = get_site_security_modules("post")
    local m, rule_table = match_rule(module.rules, body)
    if m then
        do_action(module.moduleName, rule_table)
        return true
    end

    return false
end

function _M.is_evil_body(body)
    local module = get_site_security_modules("post")
    local m, rule_table = match_rule(module.rules, body)
    if m then
        do_action(module.moduleName, rule_table)
        return true
    end

    return false
end

-- 部分上传接口/网关会从这些请求头取落盘文件名
local FILENAME_HEADERS = {
    "x-filename",
    "x-file-name",
    "x-upload-filename"
}

local function is_evil_filename_header()
    local headers = ngx.req.get_headers()

    for _, name in ipairs(FILENAME_HEADERS) do
        local value = headers[name]
        if type(value) == "table" then
            for _, item in ipairs(value) do
                if item and item ~= "" then
                    if _M.is_evil_file_ext(item, name .. ": " .. item) then
                        return true
                    end
                end
            end
        elseif value and value ~= "" then
            if _M.is_evil_file_ext(value, name .. ": " .. value) then
                return true
            end
        end
    end

    return false
end

-- 请求声明了请求体但读取失败时，fileExt 无法看到文件名/内容。
-- 有 Content-Length 或分块传输时按不可信请求处理，避免用读取失败绕过。
local function block_unreadable_body()
    local content_length = tonumber(ngx.var.content_length) or 0
    if content_length > 0 or (ngx.var.http_transfer_encoding or "") ~= "" then
        local detail = "content-length=" .. tostring(ngx.var.content_length or "") ..
            " transfer-encoding=" .. tostring(ngx.var.http_transfer_encoding or "")
        return do_upload_block("invalid_multipart:body_unreadable", detail)
    end

    return false
end

-- 二进制内容中仍可能夹带可执行代码。直接因为出现 NUL 就跳过全部文本规则，
-- 会让“正常文件头 + NUL + webshell”成为一个简单绕过。
-- 这里提取长度 >= MIN_PRINTABLE_RUN 的连续可打印片段继续检测；
-- 片段太短或纯二进制数据不参与匹配，降低图片/压缩包误报。
local function extract_printable_text(data)
    local out = {}
    local start = nil
    local n = #data

    for i = 1, n do
        local c = byte(data, i)
        if c == 9 or c == 10 or c == 13 or (c >= 32 and c <= 126) then
            if not start then
                start = i
            end
        else
            if start and i - start >= MIN_PRINTABLE_RUN then
                out[#out + 1] = sub(data, start, i - 1)
            end
            start = nil
        end
    end

    if start and n - start + 1 >= MIN_PRINTABLE_RUN then
        out[#out + 1] = sub(data, start, n)
    end

    return concat(out, "\n")
end

function _M.is_evil_request_body()
    local post_on = is_site_option_on("post")
    local file_ext_on = is_site_option_on("fileExt")

    -- post 关闭时仍需运行 fileExt（上传扩展名白名单）
    if not post_on and not file_ext_on then
        return false
    end

    -- 文件名还可能来自专用请求头；这些值不参与 multipart 解析，单独校验
    if file_ext_on and is_evil_filename_header() then
        return true
    end

    local contentType, content_type_err = get_content_type()
    local boundary, boundary_err = get_boundary()
    local is_multipart_ct = contentType ~= nil and
        matches(contentType, [[^\s*multipart/]]) ~= nil

    -- form-data
    if boundary then
        local body_raw = get_request_body()

        -- 空 body 直接放行；读取失败（有 Content-Length/分块传输但拿不到 body）
        -- 时不能跳过 fileExt，按不可信请求处理
        if body_raw == nil then
            if file_ext_on then
                return block_unreadable_body()
            end
            return false
        end

        if body_raw == "" then
            return false
        end

        -- 超大请求体按表单 part 逐个做 libinjection
        local inspect_text_only = #body_raw > MAX_BODY_INSPECT_LEN

        local blocked, saw_delimiter = upload.scan_multipart(body_raw, boundary, {
            max_file_content = MAX_FILE_CONTENT_LEN,

            -- Content-Disposition 解析失败（重复/异常 filename、嵌套 multipart 等）：
            -- 白名单开启时按不可信请求拦截，避免后端与 WAF 解析结果不一致
            on_invalid = function(cd, line)
                if not file_ext_on then
                    return false
                end

                return do_upload_block("invalid_multipart:" .. tostring(cd.invalid), line)
            end,

            -- 文件 part：filename* 和 filename 两个候选名都要检查
            on_part = function(cd, line)
                if not file_ext_on then
                    return false
                end

                -- 字段名通常不是文件名；只有明显带危险扩展名时才拦截，
                -- 避免把 name="file" 这类普通字段误判为上传文件名
                if cd.name and find(cd.name, ".", 1, true) then
                    local ok, reason = upload.check_filename(cd.name, {})
                    if not ok and match(reason, "^dangerous_extension") then
                        return do_upload_block("field_name:" .. tostring(reason), line)
                    end
                end

                for _, file_name in ipairs(upload.candidate_filenames(cd)) do
                    if _M.is_evil_file_ext(file_name, line) then
                        return true
                    end
                end

                return false
            end,

            -- 普通表单字段
            on_text = function(text)
                if not post_on then
                    return false
                end

                if _M.is_evil_body(text) then
                    return true
                end

                if inspect_text_only then
                    _M.is_sqli_or_xss(text)
                end

                return false
            end,

            -- 文件内容（只检查前 MAX_FILE_CONTENT_LEN 字节）
            on_file = function(content, cd, truncated)
                -- filename="" 但内容非空：没有可校验的扩展名，白名单模式下 fail-closed
                if file_ext_on and content ~= "" and #upload.candidate_filenames(cd) == 0 then
                    return do_upload_block("empty_filename", content)
                end

                if not post_on or content == "" then
                    return false
                end

                -- 文件 part 的正文始终经过 post 规则；fileContentCheck
                -- 只控制是否再做 libinjection 深度检测。
                -- 含 NUL 的二进制内容提取可打印片段后继续检查，避免一个 NUL
                -- 让整段文件内容跳过规则。
                local scan_content = content
                if find(content, "\0", 1, true) then
                    scan_content = extract_printable_text(content)
                    if scan_content == "" then
                        return false
                    end
                end

                if _M.is_evil_file(scan_content) then
                    return true
                end

                if is_site_option_on("fileContentCheck") then
                    return _M.is_sqli_or_xss(scan_content) and true or false
                end

                return false
            end
        })

        if blocked then
            return true
        end

        -- Content-Type 声明了 boundary，但 body 里没有分隔符：
        -- 按普通请求体整体检测，避免用畸形 multipart 绕过规则
        if not saw_delimiter then
            if post_on then
                if _M.is_evil_body(body_raw) then
                    return true
                end

                _M.is_sqli_or_xss(body_raw)
            end

            -- 无法解析出 part 就无法做扩展名白名单，fileExt 开启时按不可信请求拦截
            if file_ext_on then
                return do_upload_block("invalid_multipart:no_delimiter", body_raw)
            end

            return false
        end

        -- 小请求体仍然整体扫一遍 libinjection（规则按行匹配，避免跨行漏检）
        if post_on and not inspect_text_only then
            _M.is_sqli_or_xss(body_raw)
        end

        return false
    end

    -- Content-Type 声明 multipart 但没有可用 boundary（缺失/非法/重复/歧义），
    -- 无法解析 part 与文件名，fileExt 开启时 fail-closed
    if is_multipart_ct and file_ext_on then
        local body_raw = get_request_body()
        if body_raw == nil then
            return block_unreadable_body()
        end

        if body_raw ~= "" then
            return do_upload_block("invalid_multipart:" .. tostring(boundary_err or "no_boundary"),
                contentType)
        end

        return false
    end

    -- Content-Type 缺失/错误/重复/逗号，但正文实际是带文件的 multipart：
    -- 不能因为 CT 与正文不一致就跳过扩展名白名单
    if file_ext_on then
        local body_raw = get_request_body()
        if body_raw == nil then
            return block_unreadable_body()
        end

        -- 无/重复/歧义 Content-Type 且 body 超过 1MB：正文特征嗅探只覆盖前 1MB，
        -- 无法可靠判断 multipart，按异常请求处理
        if content_type_err and #body_raw > MAX_UNKNOWN_CT_SNIFF_LEN then
            return do_upload_block("invalid_multipart:large_body_" .. tostring(content_type_err),
                "content-length=" .. tostring(#body_raw))
        end

        if body_raw ~= "" and upload.looks_like_multipart(body_raw) then
            return do_upload_block("invalid_multipart:" .. tostring(content_type_err or "content_type_mismatch"),
                contentType or "")
        end
    end

    if not post_on then
        return false
    end

    if contentType and matches(contentType, "\\s*x-www-form-urlencoded") then
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()

        if args then
            for _, val in pairs(args) do
                local vals = val
                if type(val) == "table" then
                    vals = concat(val, ", ")
                end

                if vals and type(vals) ~= "boolean" and vals ~= "" then
                    if _M.is_evil_body(vals) then
                        return true
                    end
                    _M.is_sqli_or_xss(vals)
                end
            end
        end
    else
        local body_raw = get_request_body()
        if body_raw and body_raw ~= "" then
            if _M.is_evil_body(body_raw) then
                return true
            end
            _M.is_sqli_or_xss(body_raw)
        end
    end
end

function _M.is_evil_cookies()
    local cookie = ngx.var.http_cookie
    if is_site_option_on("cookie") and cookie then
        local module = get_site_security_modules("cookie")
        local m, rule_table = match_rule(module.rules, cookie)
        if m then
            do_action(module.moduleName, rule_table)
            return true
        end

        -- 正则先扫原始 Cookie 头，覆盖 Cookie 名和未编码的 payload；
        -- 再逐个值解码后扫一遍，避免 ..%2f、%24%7Bjndi 这类编码 payload 绕过。
        -- 不整串送检：多个 cookie 形如 "a=1; b=select ..." 拼起来会被当成一条语句，
        -- 指纹失真，还可能把相邻 cookie 拼出假阳性。
        for pair in gmatch(cookie, "[^;]+") do
            local eq = find(pair, "=", 1, true)
            local value = eq and sub(pair, eq + 1) or pair

            value = gsub(value, "^%s+", "")
            if value ~= "" then
                value = unescape_uri(value)

                local vm, vrule = match_rule(module.rules, value)
                if vm then
                    do_action(module.moduleName, vrule, value)
                    return true
                end

                _M.is_sqli_or_xss(value)
            end
        end
    end

    return false
end

function _M.is_sqli_or_xss(data)
    if data then
        local is_sqli_on = is_site_option_on("sqli")
        local is_xss_on = is_site_option_on("xss")
        if not is_sqli_on and not is_xss_on then
            return
        end

        if type(data) ~= 'table' then
            local t = {}
            t[1] = tostring(data)
            data = t
        end

        local module_sqli = get_site_security_modules("sqli")
        local module_xss = get_site_security_modules("xss")
        local rule_sqli = module_sqli.rules[1]
        local rule_xss = module_xss.rules[1]

        for _, v in pairs(data) do
            if type(v) == 'string' then
                if is_sqli_on then
                    local is_sqli = libinjection.sqli(v)
                    if is_sqli then
                        do_action(module_sqli.moduleName, rule_sqli)
                        return true
                    end
                end

                if is_xss_on then
                    local is_xss = libinjection.xss(v)
                    if is_xss then
                        do_action(module_xss.moduleName, rule_xss)
                        return true
                    end
                end
            end
        end
    end
end

return _M
