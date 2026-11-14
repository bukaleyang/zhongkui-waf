-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2026 bukale bukale2022@163.com

-- 上传文件相关解析工具：
--   * 按 RFC 2045 token 解析 Content-Disposition 参数
--   * 扩展名白名单/危险扩展名判定
--   * multipart/form-data 逐行扫描
--
-- 解析约定：
--   * 参数按 token 边界解析，其他参数值里的 filename= 不作为文件名
--   * filename / filename* 重复出现视为错误；filename* 按 RFC 2231 解码
--   * 引号未闭合、异常转义、非法 boundary 均按异常处理
--   * Content-Type 歧义（重复/逗号/缺失）由上层结合正文特征 fail-closed
--   * 嵌套 multipart 按异常处理，避免内层文件名绕过白名单

local lower = string.lower
local sub = string.sub
local find = string.find
local byte = string.byte
local char = string.char
local concat = table.concat
local insert = table.insert
local gsub = string.gsub
local match = string.match
local tonumber = tonumber
local ipairs = ipairs
local type = type

local _M = {}

local MAX_FILE_NAME_LEN = 1024

-- 服务端可直接执行的扩展名：文件名中任意一段命中即拦截
-- 用于阻断 a.php.jpg / a.jsp.png 这类“最后一段是白名单类型”的绕过
local DANGEROUS_SEGMENT_EXTS = {
    php = true, php3 = true, php4 = true, php5 = true, php6 = true, php7 = true, php8 = true,
    phtml = true, pht = true, phtm = true, phps = true, phar = true,
    jsp = true, jspx = true, jspf = true, jsw = true, jsv = true,
    asp = true, aspx = true, asa = true, asax = true, ascx = true, ashx = true, asmx = true,
    cer = true, cdx = true,
    cgi = true, pl = true, pm = true, py = true, pyc = true, rb = true, erb = true,
    sh = true, bash = true,
    exe = true, dll = true, com = true, bat = true, cmd = true, vbs = true, vbe = true,
    ps1 = true, psd1 = true, psm1 = true, msi = true, scr = true,
    jar = true, war = true, ear = true, class = true,
    hta = true, htc = true, htaccess = true, htpasswd = true, htgroup = true,
    shtml = true, shtm = true, stm = true,
    cshtml = true, vbhtml = true, razor = true,
    cfm = true, cfml = true, cfc = true,
    soap = true, rem = true, axd = true, jhtml = true,
    ["do"] = true, ["action"] = true
}

-- 只有“最后一段”是这些类型时才拦截：
-- 既做纵深防御（即使管理员把 svg/html 加进白名单也不放行），
-- 又避免把 app.js.zip 这类正常压缩包误拦
local DANGEROUS_FINAL_EXTS = {
    html = true, htm = true, xhtml = true, xht = true,
    svg = true, xml = true, xsl = true, xslt = true,
    js = true, mjs = true, wasm = true,
    swf = true,
    lua = true, sql = true,
    ini = true, env = true, conf = true, config = true
}

-- RFC 2045 tspecials: ()<>@,;:\"/[]?=
local TSPECIALS = [[()<>@,;:\"/[]?=]]
local token_char = {}
for i = 0, 255 do
    token_char[i] = (i > 32 and i < 127 and find(TSPECIALS, char(i), 1, true) == nil)
end

local function trim_spaces(s)
    return (gsub(gsub(s, "^[ \t\r\n]+", ""), "[ \t\r\n]+$", ""))
end

-- RFC 2231 / RFC 5987 的百分号解码；格式非法返回 nil
local function percent_decode(s)
    local out = {}
    local i = 1
    local n = #s

    while i <= n do
        local c = sub(s, i, i)
        if c == "%" then
            local hex = sub(s, i + 1, i + 2)
            if #hex < 2 or not match(hex, "^%x%x$") then
                return nil
            end
            insert(out, char(tonumber(hex, 16)))
            i = i + 3
        else
            insert(out, c)
            i = i + 1
        end
    end

    return concat(out)
end

local function basename(name)
    return match(name, [=[[^/\\]*$]=]) or name
end

-- 解析 Content-Disposition 行。
-- 非 Content-Disposition 行返回 nil。
-- 返回 table：
--   invalid            解析失败原因（nil 表示正常）
--   name               表单字段名
--   filename           普通 filename 参数
--   filename_star      RFC 2231 filename* 解码后的值
-- 注意：只按参数边界解析，参数值内部出现的 filename= 不会当作文件名，
-- 从而避免“文本字段值伪装成文件 part”导致内容漏检。
function _M.parse_content_disposition(line)
    if type(line) ~= "string" then
        return nil
    end

    local s = trim_spaces(line)
    local colon = find(s, ":", 1, true)
    if not colon then
        return nil
    end

    if lower(trim_spaces(sub(s, 1, colon - 1))) ~= "content-disposition" then
        return nil
    end

    local v = sub(s, colon + 1)
    local n = #v
    local pos = 1

    while pos <= n and (byte(v, pos) == 32 or byte(v, pos) == 9) do
        pos = pos + 1
    end

    local start = pos
    while pos <= n and token_char[byte(v, pos)] do
        pos = pos + 1
    end
    local dtype = lower(sub(v, start, pos - 1))

    local cd = { disposition = dtype }

    if dtype ~= "form-data" then
        cd.invalid = "bad_disposition"
        return cd
    end

    while true do
        while pos <= n and (byte(v, pos) == 32 or byte(v, pos) == 9) do
            pos = pos + 1
        end

        if pos > n then
            break
        end

        if byte(v, pos) ~= 59 then -- ';'
            cd.invalid = "bad_separator"
            return cd
        end
        pos = pos + 1

        while pos <= n and (byte(v, pos) == 32 or byte(v, pos) == 9) do
            pos = pos + 1
        end

        if pos > n then
            cd.invalid = "param_name_missing"
            return cd
        end

        local name_start = pos
        while pos <= n do
            local c = byte(v, pos)
            if c == 61 or c == 59 or c == 32 or c == 9 then -- = ; SP HTAB
                break
            end
            pos = pos + 1
        end
        local aname = lower(sub(v, name_start, pos - 1))

        while pos <= n and (byte(v, pos) == 32 or byte(v, pos) == 9) do
            pos = pos + 1
        end

        if pos > n or byte(v, pos) ~= 61 then
            cd.invalid = "param_value_missing"
            return cd
        end
        pos = pos + 1

        while pos <= n and (byte(v, pos) == 32 or byte(v, pos) == 9) do
            pos = pos + 1
        end

        if pos > n then
            cd.invalid = "param_value_missing"
            return cd
        end

        local value
        local quote = byte(v, pos)
        if quote == 34 or quote == 39 then -- " 或 '
            pos = pos + 1
            local buf = {}
            local closed = false

            while pos <= n do
                local c = byte(v, pos)

                if c == 92 then -- 反斜杠
                    if pos == n then
                        cd.invalid = "bad_escape"
                        return cd
                    end
                    local nxt = byte(v, pos + 1)
                    if nxt == quote or nxt == 92 then
                        -- 只对引号和反斜杠做反转义，其余保留（兼容 IE）
                        insert(buf, char(nxt))
                        pos = pos + 2
                    else
                        insert(buf, "\\")
                        pos = pos + 1
                    end
                elseif c == quote then
                    pos = pos + 1
                    closed = true
                    break
                elseif c == 0 or c == 13 or c == 10 then
                    cd.invalid = "control_char"
                    return cd
                else
                    insert(buf, char(c))
                    pos = pos + 1
                end
            end

            if not closed then
                cd.invalid = "unclosed_quote"
                return cd
            end

            value = concat(buf)
        else
            local value_start = pos
            while pos <= n and token_char[byte(v, pos)] do
                pos = pos + 1
            end
            value = sub(v, value_start, pos - 1)
            if value == "" then
                cd.invalid = "empty_value"
                return cd
            end
        end

        if aname == "name" then
            if cd.name ~= nil then
                cd.invalid = "duplicate_name"
                return cd
            end
            cd.name = value
        elseif aname == "filename" then
            if cd.filename ~= nil then
                cd.invalid = "duplicate_filename"
                return cd
            end
            cd.filename = value
        elseif aname == "filename*" then
            if cd.filename_star ~= nil then
                cd.invalid = "duplicate_filename_star"
                return cd
            end

            local charset, lang, encoded = match(value, "^([^']*)'([^']*)'(.*)$")
            if not charset or charset == "" then
                cd.invalid = "bad_filename_star"
                return cd
            end

            local decoded = percent_decode(encoded)
            if decoded == nil then
                cd.invalid = "bad_filename_star_encoding"
                return cd
            end

            cd.filename_star = decoded
            cd.filename_star_charset = lower(charset)
            cd.filename_star_language = lang
        else
            -- filename 的大小写/变体（fileName、file-name、x-filename 等）在不同后端行为不一致；
            -- 恰好叫 filename 的（大小写不敏感）按上面的分支正常处理，其余一律视为异常
            local normalized = gsub(aname, "[-_]", "")
            if aname ~= "filename" and find(normalized, "filename", 1, true) then
                cd.invalid = "unexpected_filename_param"
                return cd
            end
            cd.has_unknown_params = true
        end

        while pos <= n and (byte(v, pos) == 32 or byte(v, pos) == 9) do
            pos = pos + 1
        end

        if pos <= n and byte(v, pos) ~= 59 then
            cd.invalid = "bad_trailing"
            return cd
        end
    end

    if not cd.name then
        cd.invalid = "missing_name"
        return cd
    end

    return cd
end

-- 判断某个头部行是否带有指定参数（按 RFC 2045 参数边界解析）。
-- 用于发现 Content-Type 里的 filename 参数：部分非标准框架会从
-- Content-Type 取文件名，与标准 Content-Disposition 解析结果不一致。
-- 注意：不能直接对整行做 "filename" 子串匹配，否则 name="filename"
-- 之类的合法参数值会被误判。
function _M.header_has_param(line, header_name, param_name)
    if type(line) ~= "string" then
        return false
    end

    local s = trim_spaces(line)
    local colon = find(s, ":", 1, true)
    if not colon then
        return false
    end

    if header_name and lower(trim_spaces(sub(s, 1, colon - 1))) ~= header_name then
        return false
    end

    local v = sub(s, colon + 1)
    local n = #v

    -- 宽松兜底：参数顺序畸形（如 broken; filename=...）时，
    -- 仍要发现后续位置出现的 filename 参数，避免解析失败导致漏检。
    -- 先去掉引号内的值，避免 name="filename=x" 这类正常值被误判。
    if param_name == "filename" or param_name == "filename*" then
        local stripped = gsub(v, '"[^"]*"', '""')
        stripped = gsub(stripped, "'[^']*'", "''")

        local target = param_name == "filename*" and "filename%*" or "filename"
        if match(stripped, "[;%s]" .. target .. "%s*=") then
            return true
        end
    end

    local pos = find(v, ";", 1, true)
    if not pos then
        return false
    end
    pos = pos + 1

    while pos <= n do
        while pos <= n and (byte(v, pos) == 32 or byte(v, pos) == 9) do
            pos = pos + 1
        end

        if pos > n then
            break
        end

        local name_start = pos
        while pos <= n and token_char[byte(v, pos)] do
            pos = pos + 1
        end
        local aname = lower(sub(v, name_start, pos - 1))

        -- 参数名一旦确认就返回，后续值即使畸形也按“存在该参数”处理（fail-closed）。
        -- filename 还要覆盖 file-name / file_name / x-filename 等变体：
        -- 不同后端对这些非标准参数的处理不一致，不能只在值合法时才判定。
        if aname == param_name then
            return true
        end
        if param_name == "filename" and
                find(gsub(aname, "[-_]", ""), "filename", 1, true) then
            return true
        end

        while pos <= n and (byte(v, pos) == 32 or byte(v, pos) == 9) do
            pos = pos + 1
        end

        -- 参数必须紧跟 '='，否则头部已畸形，剩余部分不可信
        if pos > n or byte(v, pos) ~= 61 then
            return false
        end
        pos = pos + 1

        while pos <= n and (byte(v, pos) == 32 or byte(v, pos) == 9) do
            pos = pos + 1
        end

        if pos > n then
            return false
        end

        local quote = byte(v, pos)
        if quote == 34 or quote == 39 then
            pos = pos + 1
            local closed = false

            while pos <= n do
                local c = byte(v, pos)
                if c == 92 then -- 反转义：跳过下一个字符
                    pos = pos + 2
                elseif c == quote then
                    pos = pos + 1
                    closed = true
                    break
                else
                    pos = pos + 1
                end
            end

            if not closed then
                return false
            end
        else
            local value_start = pos
            while pos <= n and token_char[byte(v, pos)] do
                pos = pos + 1
            end
            if pos == value_start then
                return false
            end
        end

        while pos <= n and (byte(v, pos) == 32 or byte(v, pos) == 9) do
            pos = pos + 1
        end

        if pos <= n and byte(v, pos) ~= 59 then
            return false
        end
        pos = pos + 1
    end

    return false
end

-- 判断 part 头部行是否携带 filename 信息：
--   * 头名本身含 filename（如 X-Filename）
--   * 参数名是 filename / filename*（忽略 name="filename" 这种参数值）
-- 用于发现 BOM、非标准头名等导致标准 Content-Disposition 解析失败的行。
function _M.header_line_has_filename(line)
    if type(line) ~= "string" then
        return false
    end

    local s = trim_spaces(line)
    local colon = find(s, ":", 1, true)
    if not colon then
        return false
    end

    local name = lower(trim_spaces(sub(s, 1, colon - 1)))
    if find(name, "filename", 1, true) then
        return true
    end

    return _M.header_has_param(line, nil, "filename") or
        _M.header_has_param(line, nil, "filename*")
end

-- 需要做扩展名校验的文件名列表：
-- filename* 优先（Go/Python/Node/Java 等后端会优先使用它），再检查 filename
function _M.candidate_filenames(cd)
    local names = {}

    if cd and cd.filename_star and cd.filename_star ~= "" then
        names[#names + 1] = cd.filename_star
    end
    if cd and cd.filename and cd.filename ~= "" then
        names[#names + 1] = cd.filename
    end

    return names
end

-- 白名单规则归一化：只收集 state=on 的规则（白名单模式下 state 是唯一开关），
-- 去空格、转小写、去掉前导点
function _M.build_allowed(rules)
    local allowed = {}

    if type(rules) == "table" then
        for _, r in ipairs(rules) do
            if type(r) == "table" and r.state == "on" then
                local ext = r.rule
                if type(ext) == "string" then
                    ext = lower(trim_spaces(ext))
                    ext = gsub(ext, "^%.", "")
                    if ext ~= "" then
                        allowed[ext] = true
                    end
                end
            end
        end
    end

    return allowed
end

-- RFC 2046 boundary 校验：
-- boundary := 0*69<bchars> bcharsnospace
-- bcharsnospace := DIGIT / ALPHA / "'" / "(" / ")" / "+" / "_" / "," /
--                  "-" / "." / "/" / ":" / "=" / "?"
-- 长度 1-70，允许内部空格但不允许以空格结尾。
-- 非法/缺失 boundary 的 multipart 请求按不可信处理。
function _M.validate_boundary(boundary)
    if type(boundary) ~= "string" then
        return false
    end

    if #boundary < 1 or #boundary > 70 then
        return false
    end

    if byte(boundary, -1) == 32 then
        return false
    end

    return match(boundary, "^[%w_'%(%)%+_,%-%./:=? ]+$") ~= nil
end

-- 宽松百分号解码：合法 %XX 解码，非法 % 原样保留。
-- 文件名在扩展名校验前做有界解码，覆盖 %2E、%00、%2F 等编码形式。
local function percent_decode_lenient(s)
    if not find(s, "%", 1, true) then
        return nil
    end

    local out = {}
    local i = 1
    local n = #s

    while i <= n do
        local c = sub(s, i, i)
        if c == "%" then
            local hex = sub(s, i + 1, i + 2)
            if #hex == 2 and match(hex, "^%x%x$") then
                insert(out, char(tonumber(hex, 16)))
                i = i + 3
            else
                insert(out, c)
                i = i + 1
            end
        else
            insert(out, c)
            i = i + 1
        end
    end

    return concat(out)
end

-- 校验单个文件名（已经过解码/归一化）。
-- 校验点：
--   * 双扩展名：任意一段是可执行扩展名即拒绝（a.php.jpg、shell.php/.jpg）
--   * 空字节/控制字符：拒绝
--   * NTFS ADS：文件名含 ":" 即拒绝（shell.php::$DATA）
--   * 路径穿越：任何 ".." 段拒绝
--   * 无扩展名、未知扩展名：拒绝（白名单 fail-closed）
local function check_one_filename(name, allowed, max_len)
    if #name > max_len then
        return false, "oversize_filename"
    end

    for i = 1, #name do
        local c = byte(name, i)
        if c < 32 or c == 127 then
            return false, "control_char"
        end
    end

    -- RFC 2047 encoded-word（=?UTF-8?B?...?=）在 multipart filename 中非标准，
    -- 部分框架会解码，可能隐藏真实扩展名；浏览器不会发送，直接按异常拒绝
    if find(name, "=?", 1, true) and find(name, "?=", 1, true) then
        return false, "encoded_word_filename"
    end

    -- 文件名只允许 basename；仅兼容 IE 的 C:\fakepath\ 前缀。
    -- 绝对路径、盘符路径、UNC、相对路径都在这里拒绝。
    local path = gsub(name, "\\", "/")
    path = gsub(path, "^[A-Za-z]:/[Ff][Aa][Kk][Ee][Pp][Aa][Tt][Hh]/", "")

    if find(path, "/", 1, true) then
        return false, "path_not_allowed"
    end

    local base = path
    if base == "" then
        return false, "empty_filename"
    end

    -- Windows 备用数据流：shell.php:xxx / shell.jpg::$DATA
    if find(base, ":", 1, true) then
        return false, "alternate_data_stream"
    end

    local lname = lower(path)
    local lbase = lower(base)

    -- 先检查整个文件名（包含目录段）中的可执行扩展名，
    -- 防止 shell.php/.jpg 这类“最后一段是白名单类型”的绕过
    for seg in lname:gmatch("%.([%w_%-]+)") do
        if DANGEROUS_SEGMENT_EXTS[seg] then
            return false, "dangerous_extension:" .. seg
        end
    end

    local last = nil
    for seg in lbase:gmatch("%.([%w_%-]+)") do
        last = seg
    end

    if last == nil then
        return false, "no_extension"
    end

    if DANGEROUS_FINAL_EXTS[last] then
        return false, "dangerous_extension:" .. last
    end

    if not allowed[last] then
        return false, "extension_not_allowed:" .. last
    end

    return true
end

-- 返回: ok, reason
-- reason 示例: no_extension / dangerous_extension:php / extension_not_allowed:exe
function _M.check_filename(name, allowed, max_len)
    if type(name) ~= "string" then
        return false, "invalid_filename"
    end

    max_len = max_len or MAX_FILE_NAME_LEN
    if #name > max_len then
        return false, "oversize_filename"
    end

    -- 先解码再校验：恶意请求常用 %2E/%00/%2F 等编码绕过扩展名匹配。
    -- 解码只可能还原出更多危险字符，不会消除原本的危险扩展名，所以校验最终
    -- 解码结果即可覆盖原始值；最多迭代 5 次以覆盖 %252E 这类多重编码。
    local target = name
    for _ = 1, 5 do
        local decoded = percent_decode_lenient(target)
        if not decoded or decoded == target then
            break
        end
        target = decoded
    end

    -- 5 次解码后仍有合法百分号编码，说明编码层数异常；不同后端解码次数不一致，
    -- 继续放行可能让后端解出危险扩展名，按不可信文件名拒绝。
    if match(target, "%%%x%x") then
        return false, "encoded_filename_too_deep"
    end

    if #target > max_len then
        return false, "oversize_filename"
    end

    return check_one_filename(target, allowed, max_len)
end

function _M.get_extension(name)
    if type(name) ~= "string" then
        return nil
    end

    local base = basename(name)
    local last = nil
    for seg in lower(base):gmatch("%.([%w_%-]+)") do
        last = seg
    end

    return last
end

-- Content-Type 中顶层逗号表示多个 media type，按 RFC 9110 不合法。
-- 引号内的逗号（例如 boundary 参数）不参与判断。
function _M.content_type_is_ambiguous(value)
    if type(value) ~= "string" then
        return false
    end

    local in_quote = false
    local escaped = false

    for i = 1, #value do
        local c = byte(value, i)
        if escaped then
            escaped = false
        elseif in_quote and c == 92 then
            escaped = true
        elseif c == 34 then
            in_quote = not in_quote
        elseif not in_quote and c == 44 then
            return true
        end
    end

    return false
end

-- Content-Type 缺失/错误时，用正文特征判断请求是否实际为 multipart。
-- 只扫描前 1MB，避免大文件全量遍历；命中特征按不可信请求处理。
-- 头部/参数名大小写不敏感，统一转小写后再匹配。
function _M.looks_like_multipart(body)
    if type(body) ~= "string" or body == "" then
        return false
    end

    local head = lower(sub(body, 1, 1024 * 1024))
    if not find(head, "content-disposition", 1, true) then
        return false
    end
    if not find(head, "filename", 1, true) then
        return false
    end

    -- 首个非空行是分隔符，或正文中存在 "--boundary" 分隔行
    if match(head, "^%s*%-%-") then
        return true
    end

    local pos = 1
    while true do
        local s = find(head, "\n--", pos, true)
        if not s then
            break
        end
        local chunk = sub(head, s + 1, s + 4096)
        if find(chunk, "content-disposition", 1, true) then
            return true
        end
        pos = s + 3
    end

    return false
end


-- 逐行扫描 multipart/form-data。
-- opts:
--   max_file_content  单个文件内容检查上限（默认 256KB）
--   on_invalid        function(cd, line) -> true 表示拦截
--   on_part           function(cd, line) -> true 表示拦截（在 part 头解析完成后调用）
--   on_text           function(text) -> true 表示拦截
--   on_file           function(content, cd, truncated) -> true 表示拦截
-- 返回: blocked, saw_delimiter
function _M.scan_multipart(body, boundary, opts)
    opts = opts or {}

    if type(body) ~= "string" or type(boundary) ~= "string" or boundary == "" then
        return false, false
    end

    local max_file = opts.max_file_content or (256 * 1024)
    local delimiter = "--" .. boundary
    local delimiter_end = "--" .. boundary .. "--"

    local chunks = {}
    local file_chunks = {}
    local file_len = 0
    local is_file = false
    local cd = nil
    local truncated = false
    local in_headers = false
    local saw_delimiter = false

    local function flush()
        local blocked = false

        if is_file then
            if opts.on_file then
                blocked = opts.on_file(concat(file_chunks, "\n"), cd, truncated) and true or false
            end
        else
            local text = concat(chunks, "\n")
            if text ~= "" and opts.on_text then
                blocked = opts.on_text(text) and true or false
            end
        end

        chunks = {}
        file_chunks = {}
        file_len = 0
        is_file = false
        cd = nil
        truncated = false
        in_headers = false

        return blocked
    end

    local total = #body
    local pos = 1

    while pos <= total do
        local nl = find(body, "\n", pos, true)
        local raw

        if nl then
            raw = sub(body, pos, nl - 1)
            pos = nl + 1
        else
            raw = sub(body, pos)
            pos = total + 1
        end

        -- 内容行只去掉行尾 CR，避免破坏二进制/跨行 payload
        local line = raw
        if byte(line, -1) == 13 then
            line = sub(line, 1, -2)
        end

        -- boundary 允许行尾空白，但不允许行首空白（避免误把内容行当分隔符）
        -- 只在行尾确实是空格/TAB时才做一次正则，避免每行都跑 gsub
        local candidate = line
        local last_byte = byte(line, -1)
        if last_byte == 32 or last_byte == 9 then
            candidate = gsub(line, "[ \t]+$", "")
        end

        if candidate == delimiter or candidate == delimiter_end then
            saw_delimiter = true

            if flush() then
                return true, true
            end

            if candidate == delimiter_end then
                break
            end

            in_headers = true
        elseif in_headers then
            if line == "" then
                in_headers = false
            elseif byte(line, 1) == 32 or byte(line, 1) == 9 then
                -- RFC 822 折行头：后端对折行 Content-Disposition 的处理差异很大，
                -- 可能出现 WAF 看到 a.jpg、后端落盘 shell.php 的情况，按异常处理
                local folded = { invalid = "folded_header" }
                if opts.on_invalid and opts.on_invalid(folded, line) then
                    return true, true
                end

                if is_file then
                    if file_len < max_file then
                        insert(file_chunks, line)
                        file_len = file_len + #line + 1
                    else
                        truncated = true
                    end
                else
                    insert(chunks, line)
                end
            else
                local parsed = _M.parse_content_disposition(line)

                if parsed then
                    if parsed.invalid then
                        if opts.on_invalid and opts.on_invalid(parsed, line) then
                            return true, true
                        end
                        -- 解析失败时按文本继续扫描，避免漏检
                        insert(chunks, line)
                    else
                        cd = parsed

                        local names = _M.candidate_filenames(parsed)
                        -- filename 存在但为空（filename=""）也按文件 part 处理：
                        -- 内容非空时交给 on_file 做 fail-closed 判定，避免空文件名绕过扩展名校验
                        if parsed.filename ~= nil or parsed.filename_star ~= nil then
                            is_file = true
                        end

                        -- 没有 filename 的普通字段也要检查字段名：部分上传接口会用
                        -- 字段名作为落盘文件名，字段名带危险扩展名时同样拦截。
                        local name_has_dot = parsed.name and find(parsed.name, ".", 1, true) ~= nil

                        if (#names > 0 or name_has_dot) and opts.on_part then
                            if opts.on_part(parsed, line) then
                                return true, true
                            end
                        end

                        -- 普通表单字段的 Content-Disposition 行不作为内容
                    end
                elseif _M.header_has_param(line, "content-type", "filename") or
                        _M.header_has_param(line, "content-type", "filename*") then
                    -- 部分非标准框架会从 Content-Type 的 filename 参数取文件名，
                    -- 与标准 Content-Disposition 解析结果可能不一致，按异常处理
                    local bad = { invalid = "filename_in_content_type" }
                    if opts.on_invalid and opts.on_invalid(bad, line) then
                        return true, true
                    end
                    insert(chunks, line)
                elseif match(lower(line), "^%s*content%-type%s*:%s*multipart/") then
                    -- 嵌套 multipart 的内层 filename 无法用顶层扫描覆盖；
                    -- 这类结构在 form-data 中已不推荐，按异常处理
                    local bad = { invalid = "nested_multipart" }
                    if opts.on_invalid and opts.on_invalid(bad, line) then
                        return true, true
                    end
                    if not is_file then
                        insert(chunks, line)
                    end
                elseif _M.header_line_has_filename(line) then
                    -- 带 filename 但没有被解析成标准 Content-Disposition：
                    -- 可能是畸形头、BOM、非标准头名等，后端与 WAF 可能理解不一致
                    local bad = { invalid = "unparsed_filename_header" }
                    if opts.on_invalid and opts.on_invalid(bad, line) then
                        return true, true
                    end
                    if not is_file then
                        insert(chunks, line)
                    end
                elseif is_file then
                    -- 文件 part 的其余头部（Content-Type 等）跳过；
                    -- 但不是合法头部格式的行说明 part 缺少空行，按文件内容继续检查，
                    -- 避免“畸形头部 + 正文”绕过文件内容检查
                    if not match(line, "^[%w%-]+%s*:") then
                        in_headers = false

                        if file_len < max_file then
                            insert(file_chunks, line)
                            file_len = file_len + #line + 1
                        else
                            truncated = true
                        end
                    end
                else
                    -- 文本 part 的其余头部保留在文本中一起检测，
                    -- 避免把 payload 藏在 header 里绕过 Post 规则
                    insert(chunks, line)
                end
            end
        elseif line ~= "" then
            if is_file then
                if file_len < max_file then
                    local room = max_file - file_len
                    if #line > room then
                        line = sub(line, 1, room)
                        truncated = true
                    end
                    insert(file_chunks, line)
                    file_len = file_len + #line + 1
                else
                    truncated = true
                end
            else
                insert(chunks, line)
            end
        end
    end

    -- 关键：没有结束分隔符 / 请求被截断时，最后一个 part 也必须检测
    if flush() then
        return true, true
    end

    return false, saw_delimiter
end

return _M
