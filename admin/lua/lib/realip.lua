-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2026 bukale bukale2022@163.com

-- 真实 IP 配置：归一化、校验、生成/替换 nginx realip 配置块。
-- 不依赖 ngx，CIDR 校验由调用方传入。

local _M = {}

local type = type
local ipairs = ipairs
local tostring = tostring
local lower = string.lower
local match = string.match
local gsub = string.gsub
local find = string.find
local sub = string.sub
local gmatch = string.gmatch
local concat = table.concat

local DEFAULT_HEADER = "X-Forwarded-For"
local MAX_TRUSTED_PROXIES = 256

local BEGIN_MARK = "# BEGIN zhongkui-waf realip (managed)"
local END_MARK = "# END zhongkui-waf realip"

_M.DEFAULT_HEADER = DEFAULT_HEADER
_M.MAX_TRUSTED_PROXIES = MAX_TRUSTED_PROXIES
_M.BEGIN_MARK = BEGIN_MARK
_M.END_MARK = END_MARK

local function trim(s)
    return (gsub(gsub(s, "^%s+", ""), "%s+$", ""))
end

local function detect_eol(content)
    if find(content, "\r\n", 1, true) then
        return "\r\n"
    end
    return "\n"
end

-- 统一配置块行尾，避免 CRLF/LF 混用
local function to_eol(text, eol)
    text = (gsub(text, "\r\n", "\n"))
    text = (gsub(text, "\n", eol))
    return text
end

local function strip_trailing_ws(text)
    return (gsub(text, "[ \t\r\n]+$", ""))
end

local function strip_leading_blank_lines(text)
    local previous
    repeat
        previous = text
        text = (gsub(text, "^[ \t]*[\r\n]+", ""))
    until text == previous
    return text
end

local function split_list(value)
    local list = {}

    if type(value) ~= "string" then
        return list
    end

    -- 页面按行输入；同时兼容逗号/空格分隔，方便粘贴多个网段
    for item in gmatch(value, "[^,%s]+") do
        item = trim(item)
        if item ~= "" then
            list[#list + 1] = item
        end
    end

    return list
end

function _M.default()
    return {
        mode = "remote_addr",
        header = DEFAULT_HEADER,
        trustedProxies = {},
    }
end

-- 归一化为固定结构，CIDR 校验交给 validate()
function _M.normalize(cfg)
    if type(cfg) ~= "table" then
        cfg = {}
    end

    local mode = "remote_addr"
    if cfg.mode == "proxy" then
        mode = "proxy"
    end

    local header = cfg.header
    if type(header) ~= "string" then
        header = DEFAULT_HEADER
    end
    header = trim(header)
    if header == "" then
        header = DEFAULT_HEADER
    end

    local trusted = {}
    local raw = cfg.trustedProxies
    local list

    if type(raw) == "table" then
        list = raw
    else
        list = split_list(raw)
    end

    for _, item in ipairs(list) do
        if type(item) == "string" then
            item = trim(item)
            if item ~= "" then
                trusted[#trusted + 1] = item
            end
        end
    end

    return {
        mode = mode,
        header = header,
        trustedProxies = trusted,
    }
end

-- is_valid_cidr(cidr) -> boolean, err
function _M.validate(cfg, is_valid_cidr)
    if type(cfg) ~= "table" then
        return false, "配置格式不正确"
    end

    if cfg.mode ~= "remote_addr" and cfg.mode ~= "proxy" then
        return false, "获取方式不正确"
    end

    -- 直接使用连接地址时不需要代理头和可信代理
    if cfg.mode == "remote_addr" then
        return true
    end

    local header = cfg.header
    if type(header) ~= "string" or header == "" then
        return false, "代理头不能为空"
    end

    if #header > 64 or not match(header, "^[A-Za-z0-9][A-Za-z0-9%-]*$") then
        return false, "代理头格式不正确，只能包含字母、数字和连字符"
    end

    if lower(header) == "proxy_protocol" then
        return false, "proxy_protocol 需要在 listen 指令中启用，页面暂不支持"
    end

    local proxies = cfg.trustedProxies
    if type(proxies) ~= "table" or #proxies == 0 then
        return false, "使用代理头时必须配置可信代理"
    end

    if #proxies > MAX_TRUSTED_PROXIES then
        return false, "可信代理数量过多，最多 " .. MAX_TRUSTED_PROXIES .. " 个"
    end

    for _, cidr in ipairs(proxies) do
        if cidr == "0.0.0.0/0" or cidr == "::/0" then
            return false, "不能信任所有地址，请填写具体的代理/CDN 网段"
        end

        -- 只允许 IP/CIDR 字符，避免把任意文本写进 nginx 配置
        if not match(cidr, "^[%x:%.%/]+$") then
            return false, "可信代理格式不正确: " .. tostring(cidr)
        end

        if type(is_valid_cidr) ~= "function" then
            return false, "缺少可信代理校验函数"
        end

        local ok, err = is_valid_cidr(cidr)
        if not ok then
            return false, "可信代理格式不正确: " .. tostring(cidr) ..
                (err and (" (" .. tostring(err) .. ")") or "")
        end
    end

    return true
end

-- 生成 nginx http 上下文可用的 realip 配置块。
function _M.build_block(cfg)
    local c = _M.normalize(cfg)
    local lines = {
        BEGIN_MARK,
        "# 本段由钟馗 WAF 系统设置生成，请勿手工修改",
    }

    if c.mode == "proxy" then
        for _, cidr in ipairs(c.trustedProxies) do
            lines[#lines + 1] = "set_real_ip_from " .. cidr .. ";"
        end

        lines[#lines + 1] = "real_ip_header " .. c.header .. ";"

        if lower(c.header) == "x-forwarded-for" then
            -- XFF 可能包含多级代理，必须从右往左跳过可信代理
            lines[#lines + 1] = "real_ip_recursive on;"
        else
            -- 单值头（X-Real-IP/CF-Connecting-IP 等）不需要递归
            lines[#lines + 1] = "real_ip_recursive off;"
        end
    else
        lines[#lines + 1] = "# mode=remote_addr，直接使用连接地址"
    end

    lines[#lines + 1] = END_MARK
    return concat(lines, "\n") .. "\n"
end

-- 替换文件中的托管块，不存在时追加；沿用文件行尾，块前后各留一个空行
function _M.replace_block(content, block, eol)
    content = content or ""
    block = block or ""
    eol = eol or detect_eol(content)

    block = to_eol(block, eol)
    if sub(block, -#eol) ~= eol then
        block = block .. eol
    end

    local begin_pos = find(content, BEGIN_MARK, 1, true)
    local end_pos = find(content, END_MARK, 1, true)

    if begin_pos and end_pos and end_pos > begin_pos then
        local line_end = find(content, "\n", end_pos, true)
        local prefix = strip_trailing_ws(sub(content, 1, begin_pos - 1))
        local suffix = line_end and sub(content, line_end + 1) or ""
        suffix = strip_leading_blank_lines(suffix)

        local result = ""
        if prefix ~= "" then
            result = prefix .. eol .. eol
        end

        result = result .. block

        if suffix ~= "" then
            result = result .. eol .. suffix
        end

        return result
    end

    content = strip_trailing_ws(content)
    if content == "" then
        return block
    end

    return content .. eol .. eol .. block
end

return _M
