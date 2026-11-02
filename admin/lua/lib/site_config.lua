-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

local cjson = require "cjson"
local config = require "config"
local file = require "file_utils"
local rule_utils = require "lib.rule_utils"
local nkeys = require "table.nkeys"

local pairs = pairs
local concat = table.concat
local format = string.format
local tostring = tostring
local pcall = pcall
local gsub = string.gsub
local read_file_to_string = file.read_file_to_string
local write_string_to_file_atomic = file.write_string_to_file_atomic
local cjson_decode = cjson.decode

local _M = {}

local WEBSITES_PATH = config.CONF_PATH .. '/website.json'
local CERTIFICATE_PATH = config.CONF_PATH .. "/certificate.json"
local SITES_CONF_PATH = config.ZHONGKUI_PATH .. '/admin/conf/sites.conf'
local ACME_WEBROOT = gsub(config.ZHONGKUI_PATH .. '/data/acme/webroot', '\\', '/')

-- ACME HTTP-01 验证文件目录
local ACME_CHALLENGE_CONFIG = [[
    location ^~ /.well-known/acme-challenge/ {
        root "%s";
        default_type text/plain;
        try_files $uri =404;
        access_log off;
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

-- 生成站点配置文件
function _M.generate()
    local json = read_file_to_string(WEBSITES_PATH)
    if not json then
        return write_string_to_file_atomic(SITES_CONF_PATH, '')
    end

    local ok, rule_table = pcall(cjson_decode, json)
    if not ok or type(rule_table) ~= 'table' then
        -- 配置无法解析时保持现有 sites.conf 不变
        ngx.log(ngx.ERR, "failed to parse ", WEBSITES_PATH)
        return nil, "failed to parse " .. WEBSITES_PATH
    end

    local sites = rule_table.rules
    local ngxConfig = ''

    if sites and nkeys(sites) > 0 then
        for _, site in pairs(sites) do
            local serverNames = site.serverNames

            if serverNames and nkeys(serverNames) > 0 then
                local serverNameStr = concat(serverNames, ' ')
                local sslCertConfigStr = ''
                local cert = nil
                local challengeConfig = format(ACME_CHALLENGE_CONFIG, ACME_WEBROOT)
                local hasHttp80 = false
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

                local listenPortsStr = ''
                for _, p in pairs(site.listenPorts or {}) do
                    local isSSL = (p.ssl == 'on' or p.ssl == true)

                    if tostring(p.port) == '80' then
                        if isSSL then
                            hasSsl80 = true
                        else
                            hasHttp80 = true
                        end
                    end

                    if isSSL and not cert then
                        -- 没有可用证书时跳过 SSL 端口，避免生成无法加载的配置
                        ngx.log(ngx.ERR, "site ", serverNameStr, " has no available certificate, skip ssl port ", tostring(p.port))
                    else
                        local sslStr = isSSL and ' ssl' or ''
                        listenPortsStr = listenPortsStr .. '    listen ' .. p.port .. sslStr .. ';\n'
                    end
                end

                if listenPortsStr ~= '' then
                    ngxConfig = ngxConfig .. format(NGINX_SERVER_CONFIG, listenPortsStr, serverNameStr, challengeConfig, sslCertConfigStr, site.upstream or '')
                end

                -- 只有 443 或其它端口的站点，额外生成 80 端口验证 server
                if not hasHttp80 and not hasSsl80 then
                    ngxConfig = ngxConfig .. format(CHALLENGE_SERVER_CONFIG, serverNameStr, challengeConfig)
                elseif hasSsl80 and not hasHttp80 then
                    ngx.log(ngx.ERR, "site ", serverNameStr, " listens on port 80 with ssl, ACME HTTP-01 is unavailable")
                end
            end
        end
    end

    return write_string_to_file_atomic(SITES_CONF_PATH, ngxConfig)
end

return _M
