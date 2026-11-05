-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

local cjson = require "cjson"
local config = require "config"
local file = require "file_utils"
local rule_utils = require "lib.rule_utils"
local nkeys = require "table.nkeys"

local pairs = pairs
local ipairs = ipairs
local concat = table.concat
local format = string.format
local tostring = tostring
local tonumber = tonumber
local pcall = pcall
local gsub = string.gsub
local find = string.find
local date = os.date
local rename = os.rename
local read_file_to_string = file.read_file_to_string
local write_string_to_file_atomic = file.write_string_to_file_atomic
local cjson_decode = cjson.decode

local _M = {}

-- 最近一次 generate() 产生的告警，调用方（面板保存/重载）可读取后提示运维
local last_warnings = {}

local WEBSITES_PATH = config.CONF_PATH .. '/website.json'
local CERTIFICATE_PATH = config.CONF_PATH .. "/certificate.json"
local SITES_CONF_PATH = config.ZHONGKUI_PATH .. '/admin/conf/sites.conf'
local ACME_WEBROOT = gsub(config.ZHONGKUI_PATH .. '/data/acme/webroot', '\\', '/')
local ACME_LOCATION_PATH = '/.well-known/acme-challenge'

local SITE_CONF_ROOT = config.CONF_PATH .. '/sites'
local FRAGMENT_FILE = 'nginx.conf'
local FRAGMENT_MAX_SIZE = 16 * 1024

local ACME_CHALLENGE_CONFIG = [[
    location ^~ /.well-known/acme-challenge/ {
        # 平台 ACME 路径不受自定义配置里的 allow/deny、auth_basic 影响
        allow all;
        auth_basic off;

        root "%s";
        default_type text/plain;
        try_files $uri =404;
        access_log off;
    }
]]

-- HTTP 业务块的 ACME 守卫：在 server-rewrite 阶段截断自定义片段里的 return/rewrite/if
local HTTP_ACME_GUARD = [[
    if ($uri ~ ^/\.well-known/acme-challenge/) {
        break;
    }
]]

-- nginx server
local NGINX_SERVER_CONFIG = [[
server {
%s
    server_name %s;

    charset utf-8;

%s
%s
%s
%s
    location / {
        proxy_pass %s;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP  $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Port $server_port;
    }
}
]]

-- 仅用于 ACME 验证的临时 80 端口 server，避免 SSL-only 站点无法申请证书
local CHALLENGE_SERVER_CONFIG = [[
server {
    listen 80;

    server_name %s;

    charset utf-8;

%s
    location / {
        return 404;
    }
}
]]

-- 强制 HTTPS 的跳转块：不加载站点片段（片段里的 location 会抢在跳转之前命中）
local REDIRECT_SERVER_CONFIG = [[
server {
%s
    server_name %s;

    charset utf-8;

    # 跳过 WAF 的 access 阶段，避免验证码/CC 拦截页代替跳转（不能用空块，nginx 会报错）
    access_by_lua_block { return }

%s
    location / {
        return 308 %s;
    }
}
]]

-- 兜底：未命中域名的请求直接断开，避免落到首个站点，也让跳转块无法反射 Host
local DEFAULT_SERVER_CONFIG = [[
server {
    listen 80 default_server;
    server_name _;

    access_by_lua_block { return }

    location / {
        return 444;
    }
}
]]

-- ssl certificate
local SSL_CERT_CONFIG = [[
    ssl_certificate      %s;
    ssl_certificate_key  %s;

    ssl_session_cache    shared:SSL:1m;
    ssl_session_timeout  5m;

    ssl_ciphers  HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers  on;
]]

-- 获取站点绑定的证书，证书不存在或缺少文件路径时返回 nil
local function get_site_cert(cert_id)
    if not cert_id then
        return nil
    end

    local response = rule_utils.get_rule(CERTIFICATE_PATH, cert_id)
    local cert = response and response.data
    if cert and cert.certPath and cert.keyPath
        and file.is_file_exists(cert.certPath) and file.is_file_exists(cert.keyPath) then
        return cert
    end

    if cert then
        ngx.log(ngx.ERR, "certificate files missing for cert id ", tostring(cert_id))
    end

    return nil
end

local function fragment_dir(site_id)
    return SITE_CONF_ROOT .. '/' .. tostring(site_id)
end

local function fragment_path(site_id)
    return fragment_dir(site_id) .. '/' .. FRAGMENT_FILE
end

local function fragment_template()
    return '# 本文件由站点的“高级配置”维护，重新生成站点配置时不会被覆盖\n'
        .. '# 仅支持 server / location 级指令，例如 client_max_body_size、proxy_read_timeout、add_header\n'
        .. '# 不允许：server{} / upstream{} / listen / server_name / include / 任何 lua 指令\n'
end

-- 确保片段目录与文件存在，缺失时补模板
local function ensure_fragment(site_id)
    if not file.is_directory(SITE_CONF_ROOT) then
        local ok, err = file.mkdir(SITE_CONF_ROOT)
        if not ok and not file.is_directory(SITE_CONF_ROOT) then
            return nil, '创建目录失败: ' .. tostring(err)
        end
    end

    local dir = fragment_dir(site_id)
    if not file.is_directory(dir) then
        local ok, err = file.mkdir(dir)
        if not ok and not file.is_directory(dir) then
            return nil, '创建目录失败: ' .. tostring(err)
        end
    end

    local path = fragment_path(site_id)
    if not file.is_file_exists(path) then
        local ok, err = write_string_to_file_atomic(path, fragment_template())
        if not ok then
            return nil, '写入模板失败: ' .. tostring(err)
        end
    end

    return path
end

-- 固定文件名 include：只加载面板管理的这一个文件，避免同目录其它 .conf 被意外引入
local function fragment_include(site_id)
    local path = gsub(fragment_path(site_id), '\\', '/')
    return format('\n    # ==== 站点自定义配置：%s ====\n    include "%s";\n', path, path)
end

-- 强制 HTTPS 的跳转目标：优先 443（不写端口），否则取第一个可用的 ssl 端口
local function redirect_target(https_ports)
    local port = https_ports[1]
    for _, p in ipairs(https_ports) do
        if p == '443' then
            port = '443'
            break
        end
    end

    if port == '443' then
        return 'https://$host$request_uri'
    end

    return 'https://$host:' .. port .. '$request_uri'
end

-- 生成 listen 行，options 用于追加 " ssl"
local function listen_lines(ports, options)
    local lines = {}
    for _, port in ipairs(ports) do
        lines[#lines + 1] = format('    listen %s%s;\n', port, options or '')
    end

    return concat(lines)
end

-- 校验站点是否存在
local function site_exists(site_id)
    local json = read_file_to_string(WEBSITES_PATH)
    if not json then
        return false
    end

    local ok, rule_table = pcall(cjson_decode, json)
    if not ok or type(rule_table) ~= 'table' or type(rule_table.rules) ~= 'table' then
        return false
    end

    for _, site in pairs(rule_table.rules) do
        if tonumber(site.id) == site_id then
            return true
        end
    end

    return false
end

-- 剥离注释：引号可跨行；nginx 只在 token 起始位置把 # 当注释
local function strip_comments(text)
    local out = {}
    local quote = nil
    local escaped = false
    local last_space = true
    local start = 1
    local i, n = 1, #text

    while i <= n do
        local c = text:sub(i, i)

        if quote then
            if escaped then
                escaped = false
            elseif c == '\\' then
                escaped = true
            elseif c == quote then
                quote = nil
                last_space = false
            end
        elseif c == '"' or c == "'" then
            quote = c
            escaped = false
            last_space = false
        elseif c == '\\' and i < n then
            -- 转义字符属于当前 token
            i = i + 1
            last_space = false
        elseif c == '#' and last_space then
            out[#out + 1] = text:sub(start, i - 1)
            local nl = find(text, '\n', i, true)
            if not nl then
                return concat(out)
            end
            out[#out + 1] = '\n'
            i = nl
            start = nl + 1
            last_space = true
        elseif c == ';' then
            last_space = true
        elseif c == '{' or c == '}' then
            -- token 中间的 { } 不改变 token 起始状态
        elseif c == ' ' or c == '\t' or c == '\r' or c == '\n' then
            last_space = true
        else
            last_space = false
        end

        i = i + 1
    end

    out[#out + 1] = text:sub(start)
    return concat(out)
end

-- 提取指令名和参数（支持一行多条、引号、转义）
local function each_directive(text)
    local directives = {}
    local current = nil
    local stmt_start = true
    local i, n = 1, #text

    while i <= n do
        local c = text:sub(i, i)

        if c == '\\' and i < n then
            -- 转义字符属于当前 token，不能把 \; \{ \} 当成语句或块边界
            if current then
                current.args = current.args .. text:sub(i, i + 1)
            end
            stmt_start = false
            i = i + 2
        elseif c == '"' or c == "'" then
            local quote = c
            local s = i
            i = i + 1
            while i <= n do
                local ch = text:sub(i, i)
                if ch == '\\' then
                    i = i + 2
                elseif ch == quote then
                    i = i + 1
                    break
                else
                    i = i + 1
                end
            end
            if current then
                current.args = current.args .. text:sub(s, i - 1)
            end
            stmt_start = false
        elseif c == ';' or c == '{' or c == '}' then
            if current then
                directives[#directives + 1] = current
                current = nil
            end
            stmt_start = true
            i = i + 1
        elseif c == ' ' or c == '\t' or c == '\r' or c == '\n' then
            if current and current.args ~= '' and current.args:sub(-1) ~= ' ' then
                current.args = current.args .. ' '
            end
            i = i + 1
        elseif stmt_start then
            local s, e = find(text, '^[%w_]+', i)
            if s then
                current = {name = text:sub(s, e), args = ''}
                i = e + 1
            else
                i = i + 1
            end
            stmt_start = false
        else
            if current then
                current.args = current.args .. c
            end
            i = i + 1
        end
    end

    if current then
        directives[#directives + 1] = current
    end

    return directives
end

-- 解析 location 路径（兼容 = /、^~ /、~ / 及 =/ 等紧凑写法）
local function parse_location_path(args)
    local i, n = 1, #args

    local function skip_space()
        while i <= n and args:sub(i, i) == ' ' do
            i = i + 1
        end
    end

    local function read_token()
        skip_space()
        if i > n then
            return nil
        end

        local c = args:sub(i, i)
        if c == '"' or c == "'" then
            local quote = c
            local buf = {}
            i = i + 1
            while i <= n do
                local ch = args:sub(i, i)
                if ch == '\\' and i < n then
                    buf[#buf + 1] = args:sub(i + 1, i + 1)
                    i = i + 2
                elseif ch == quote then
                    i = i + 1
                    break
                else
                    buf[#buf + 1] = ch
                    i = i + 1
                end
            end
            return concat(buf)
        end

        local s = i
        while i <= n and args:sub(i, i) ~= ' ' do
            i = i + 1
        end
        return args:sub(s, i - 1)
    end

    local first = read_token()
    if not first then
        return nil
    end

    if first == '=' or first == '^~' or first == '~' or first == '~*' then
        return read_token()
    end

    -- nginx 也接受 =/、^~/、~/、~*/ 这种紧凑写法
    local compact = first:match('^%^~(.+)$') or first:match('^~%*(.+)$')
        or first:match('^=(.+)$') or first:match('^~(.+)$')
    return compact or first
end

-- 判断是否为 ACME 根路径，避免误伤 /docs/.well-known/... 这类普通路径
local function is_acme_location(path)
    if not path then
        return false
    end

    -- 去掉正则转义和行首锚点
    local plain_path = gsub(path, '\\', '')
    plain_path = gsub(plain_path, '^%^', '')

    if plain_path:sub(1, #ACME_LOCATION_PATH) ~= ACME_LOCATION_PATH then
        return false
    end

    local next_char = plain_path:sub(#ACME_LOCATION_PATH + 1, #ACME_LOCATION_PATH + 1)
    return next_char == '' or next_char == '/' or next_char == '$'
end

-- 花括号配对检查
local function check_braces(text)
    local depth, quote, i = 0, nil, 1
    while i <= #text do
        local c = text:sub(i, i)
        if quote then
            if c == '\\' then
                i = i + 1
            elseif c == quote then
                quote = nil
            end
        elseif c == '"' or c == "'" then
            quote = c
        elseif c == '\\' then
            -- 转义的 { } 不参与配对
            i = i + 1
        elseif c == '{' then
            depth = depth + 1
        elseif c == '}' then
            depth = depth - 1
            if depth < 0 then
                return nil, '花括号不匹配，请检查自定义配置'
            end
        end
        i = i + 1
    end

    if depth ~= 0 then
        return nil, '花括号不匹配，请检查自定义配置'
    end

    return true
end

-- 片段位于 server 级，权限较高，保存前做必要校验
local function validate_fragment(text)
    if #text > FRAGMENT_MAX_SIZE then
        return '自定义配置过长，上限 16KB'
    end

    -- NUL 等二进制字符会被 nginx 拒绝，提前拦截
    if find(text, '\0', 1, true) then
        return '自定义配置包含不可见字符，请检查是否粘贴了二进制内容'
    end

    local plain = strip_comments(text)

    for _, directive in ipairs(each_directive(plain)) do
        local name = directive.name

        if name == 'listen' or name == 'server_name' then
            return '不允许在自定义配置中修改 listen / server_name，请在站点基本信息中设置'
        end

        if find(name, 'by_lua', 1, true) or name:sub(1, 4) == 'lua_' then
            return '不允许使用 lua 相关指令（会绕过 WAF 检测）'
        end

        if name == 'include' then
            return '不允许在自定义配置中使用 include'
        end

        if name == 'ssl_certificate' or name == 'ssl_certificate_key' then
            return '不允许修改证书配置，请在证书管理中操作'
        end

        if name == 'location' then
            local path = parse_location_path(directive.args)

            if path == '/' then
                return '不能重复定义根路径 location /，请使用更长前缀（如 location /api/）或把指令写在 server 级'
            end

            if is_acme_location(path) then
                return '不能重复定义 ACME 验证路径，该路径由系统自动生成'
            end
        end
    end

    local braces_ok, braces_err = check_braces(plain)
    if not braces_ok then
        return braces_err
    end

    return nil
end

-- 内容未变化时不写盘
local function write_sites_conf_if_changed(content)
    local current = read_file_to_string(SITES_CONF_PATH)
    if current == content then
        return true
    end

    return write_string_to_file_atomic(SITES_CONF_PATH, content)
end

-- 生成站点配置
function _M.generate()
    last_warnings = {}

    local json = read_file_to_string(WEBSITES_PATH)
    if not json then
        return write_sites_conf_if_changed('')
    end

    local ok, rule_table = pcall(cjson_decode, json)
    if not ok or type(rule_table) ~= 'table' then
        -- 配置无法解析时保持现有 sites.conf 不变
        ngx.log(ngx.ERR, "failed to parse ", WEBSITES_PATH)
        return nil, "站点数据解析失败"
    end

    local sites = rule_table.rules
    local ngxConfig = ''

    if sites and nkeys(sites) > 0 then
        for _, site in pairs(sites) do
            local serverNames = site.serverNames

            if serverNames and nkeys(serverNames) > 0 then
                -- 固定 include 要求文件必须存在，缺失时补模板，避免 nginx 启动失败
                local _, ensure_err = ensure_fragment(site.id)
                if ensure_err then
                    ngx.log(ngx.ERR, "failed to prepare site fragment for ", tostring(site.id), ": ", tostring(ensure_err))
                    return nil, "站点自定义配置目录不可写"
                end

                local serverNameStr = concat(serverNames, ' ')
                local sslCertConfigStr = ''
                local cert = nil
                local challengeConfig = format(ACME_CHALLENGE_CONFIG, ACME_WEBROOT)
                local hasSsl80 = false

                for _, p in pairs(site.listenPorts or {}) do
                    if p.ssl == 'on' or p.ssl == true then
                        cert = get_site_cert(site.certId)
                        break
                    end
                end

                if cert then
                    sslCertConfigStr = format(SSL_CERT_CONFIG, cert.certPath, cert.keyPath)
                end

                -- 80 恒为明文端口，是否跳转由强制 HTTPS 决定
                local httpPorts, httpsPorts = {}, {}
                local hasUser80 = false
                for _, p in pairs(site.listenPorts or {}) do
                    local isSSL = (p.ssl == 'on' or p.ssl == true)
                    local port = tostring(p.port)

                    if port == '80' then
                        hasUser80 = true
                        hasSsl80 = hasSsl80 or isSSL
                        httpPorts[#httpPorts + 1] = port
                    elseif isSSL and not cert then
                        -- 证书不可用时跳过，避免生成加载不了的配置
                        last_warnings[#last_warnings + 1] = format('站点 %s 的 HTTPS 端口 %s 已跳过：证书不可用',
                            serverNameStr, port)
                        ngx.log(ngx.ERR, "site ", serverNameStr, " has no available certificate, skip ssl port ", port)
                    elseif isSSL then
                        httpsPorts[#httpsPorts + 1] = port
                    else
                        httpPorts[#httpPorts + 1] = port
                    end
                end

                local forceHttps = (site.forceHttps == 'on' or site.forceHttps == true)
                local canRedirect = forceHttps and #httpsPorts > 0

                if forceHttps and not canRedirect then
                    last_warnings[#last_warnings + 1] = format('站点 %s 的强制 HTTPS 未生效：缺少可用的 HTTPS 端口',
                        serverNameStr)
                end

                -- 强制 HTTPS 生效后，明文端口全部改走跳转，避免“只跳 80、8080 仍可明文访问”
                local redirectPorts = { '80' }
                if canRedirect then
                    for _, port in ipairs(httpPorts) do
                        if port ~= '80' then
                            redirectPorts[#redirectPorts + 1] = port
                        end
                    end
                    httpPorts = {}
                    sslCertConfigStr = sslCertConfigStr
                        .. '\n    add_header Strict-Transport-Security "max-age=31536000" always;\n'
                end

                -- 80 块始终存在：强制 HTTPS 时跳转，未配置 80 时只做证书验证
                if canRedirect then
                    local target = redirect_target(httpsPorts)
                    ngxConfig = ngxConfig .. format(REDIRECT_SERVER_CONFIG, listen_lines(redirectPorts),
                        serverNameStr, challengeConfig, target)
                elseif not hasUser80 then
                    ngxConfig = ngxConfig .. format(CHALLENGE_SERVER_CONFIG, serverNameStr, challengeConfig)
                end

                -- HTTP 业务块
                if #httpPorts > 0 then
                    ngxConfig = ngxConfig .. format(NGINX_SERVER_CONFIG, listen_lines(httpPorts), serverNameStr,
                        '', HTTP_ACME_GUARD, fragment_include(site.id), challengeConfig, site.upstream or '')
                end

                -- HTTPS 业务块：ACME 只走 80（HTTP-01），这里不需要验证路径
                if #httpsPorts > 0 then
                    ngxConfig = ngxConfig .. format(NGINX_SERVER_CONFIG, listen_lines(httpsPorts, ' ssl'), serverNameStr,
                        sslCertConfigStr, '', fragment_include(site.id), '', site.upstream or '')
                end

                if hasSsl80 then
                    last_warnings[#last_warnings + 1] = format('站点 %s 的 80 端口 SSL 标记已忽略', serverNameStr)
                    ngx.log(ngx.ERR, "site ", serverNameStr, " sets ssl on port 80, the flag is ignored")
                end
            end
        end
    end

    -- 未命中任何域名的请求直接断开，避免落到首个站点，也让跳转块无法反射 Host
    ngxConfig = ngxConfig .. DEFAULT_SERVER_CONFIG

    return write_sites_conf_if_changed(gsub(ngxConfig, '\n\n\n+', '\n\n'))
end

-- 生成告警（端口被跳过、强制 HTTPS 未生效）拼进响应提示，避免静默降级
function _M.append_warnings(response)
    if #last_warnings == 0 then
        return response
    end

    local text = concat(last_warnings, '；')
    response.msg = (response.msg and response.msg ~= '') and (response.msg .. '；' .. text) or text
    return response
end

-- 站点绑定的证书是否可用（记录存在且证书文件在盘上），供保存校验使用
function _M.is_cert_usable(cert_id)
    return get_site_cert(cert_id) ~= nil
end

-- 文件不存在时返回模板说明（只读）
function _M.get_site_fragment(site_id)
    site_id = tonumber(site_id)
    if not site_id then
        return nil, '站点 ID 无效'
    end

    if not site_exists(site_id) then
        return nil, '站点不存在'
    end

    local path = fragment_path(site_id)
    if not file.is_file_exists(path) then
        return fragment_template()
    end

    -- 读不到时不能返回空串，否则前端会显示空编辑器，容易被当成已清空
    local content = read_file_to_string(path)
    if content == nil then
        ngx.log(ngx.ERR, "failed to read site fragment ", path)
        return nil, '读取自定义配置失败，请稍后重试'
    end

    return content
end

-- 保存：校验 -> 写入 -> 生成 -> nginx -t -> 失败回滚 -> 重载
function _M.save_site_fragment(site_id, content)
    site_id = tonumber(site_id)
    if not site_id then
        return {code = 400, msg = '站点 ID 无效'}
    end

    if not site_exists(site_id) then
        return {code = 400, msg = '站点不存在，请刷新后重试'}
    end

    -- content 非字符串时不能当成空内容清空配置
    if type(content) ~= 'string' then
        return {code = 400, msg = '自定义配置参数格式不正确，请刷新页面后重试'}
    end
    -- 去掉 BOM，否则首行指令会被当成未知指令
    content = gsub(content, '^\239\187\191', '')
    content = gsub(content, '\r\n', '\n')
    content = gsub(content, '\r', '\n')

    local invalid = validate_fragment(content)
    if invalid then
        return {code = 400, msg = invalid}
    end

    local path, ensure_err = ensure_fragment(site_id)
    if not path then
        ngx.log(ngx.ERR, "failed to prepare site fragment for ", tostring(site_id), ": ", tostring(ensure_err))
        return {code = 500, msg = '保存自定义配置失败，请检查站点配置目录权限'}
    end

    -- ensure 之后文件必然存在，读不到说明权限或占用异常，继续写会把旧内容丢掉
    local old_content = read_file_to_string(path)
    if old_content == nil then
        ngx.log(ngx.ERR, "failed to read site fragment ", path)
        return {code = 500, msg = '读取现有自定义配置失败，请稍后重试'}
    end
    local old_conf = read_file_to_string(SITES_CONF_PATH)

    -- 空内容保留模板说明
    if gsub(content, '%s+', '') == '' then
        content = fragment_template()
    end

    local written, write_err = write_string_to_file_atomic(path, content)
    if not written then
        ngx.log(ngx.ERR, "failed to write site fragment ", path, ": ", tostring(write_err))
        return {code = 500, msg = '写入自定义配置失败，请稍后重试'}
    end

    -- 片段与 sites.conf 必须一起回滚
    local function rollback()
        local ok, err = write_string_to_file_atomic(path, old_content)
        if not ok then
            ngx.log(ngx.ERR, "failed to restore site fragment ", path, ": ", tostring(err))
        end

        if old_conf then
            ok, err = write_string_to_file_atomic(SITES_CONF_PATH, old_conf)
        else
            ok, err = _M.generate()
        end
        if not ok then
            ngx.log(ngx.ERR, "failed to restore ", SITES_CONF_PATH, ": ", tostring(err))
        end
    end

    local generated, gen_err = _M.generate()
    if not generated then
        rollback()
        return {code = 500, msg = '生成站点配置失败: ' .. tostring(gen_err)}
    end

    local passed, detail = config.test_nginx_config_detail()
    if not passed then
        -- nginx 仍在运行旧配置，回滚文件即可，不需要 reload
        rollback()
        return {code = 500, msg = '自定义配置未通过 nginx 校验，已回滚', detail = detail}
    end

    -- 已经做过 -t，这里跳过 reload_nginx() 内部的重复校验
    local reloaded, reload_err = config.reload_config_file(true)
    if not reloaded then
        rollback()
        -- reload 失败时运行态不确定，恢复文件后再尝试一次重载
        local restored, restored_err = config.reload_config_file(true)
        local msg = 'nginx 重载失败，已回滚'
        if not restored then
            msg = 'nginx 重载失败，已回滚文件，但恢复重载仍失败'
            ngx.log(ngx.ERR, "failed to reload after rollback: ", tostring(restored_err))
        end
        return {code = 500, msg = msg, detail = tostring(reload_err)}
    end

    return _M.append_warnings({code = 200, msg = '自定义配置已保存并生效'})
end

-- 手工修改片段后的重新生成与重载
function _M.reload_site_config()
    -- generate() 会先写盘，校验失败时要把旧内容还原，避免磁盘上留下无法加载的配置。
    -- 注意：如果失败原因是片段文件本身，还原 sites.conf 也救不了重启，但至少不会让
    -- sites.conf 与运行中的配置不一致
    local old_conf = read_file_to_string(SITES_CONF_PATH)

    local generated, gen_err = _M.generate()
    if not generated then
        return {code = 500, msg = '生成站点配置失败: ' .. tostring(gen_err)}
    end

    local passed, detail = config.test_nginx_config_detail()
    if not passed then
        if old_conf then
            local ok, err = write_string_to_file_atomic(SITES_CONF_PATH, old_conf)
            if not ok then
                ngx.log(ngx.ERR, "failed to restore ", SITES_CONF_PATH, ": ", tostring(err))
            end
        end

        return {code = 500, msg = 'nginx 配置校验失败', detail = detail}
    end

    local reloaded, reload_err = config.reload_config_file(true)
    if not reloaded then
        return {code = 500, msg = 'nginx 重载失败', detail = tostring(reload_err)}
    end

    return _M.append_warnings({code = 200, msg = '配置已重载'})
end

-- 删除站点时归档整个片段目录，避免 id 复用时旧配置生效
function _M.archive_site_fragment(site_id)
    site_id = tonumber(site_id)
    if not site_id then
        return true
    end

    local dir = fragment_dir(site_id)
    if not file.is_directory(dir) then
        return true
    end

    local base = dir .. '.removed.' .. date('%Y%m%d%H%M%S')
    local target = base
    local suffix = 1

    -- 避免同秒归档目录重名
    while file.is_file_exists(target) do
        suffix = suffix + 1
        target = base .. '.' .. suffix
    end

    local ok, err = rename(dir, target)
    if not ok then
        ngx.log(ngx.ERR, "failed to archive site config directory ", dir, ": ", tostring(err))
        return nil, err
    end

    return true
end

return _M
