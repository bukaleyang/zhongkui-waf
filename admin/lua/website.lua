-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

local cjson = require "cjson"
local config = require "config"
local file = require "file_utils"
local user = require "user"
local rule_utils = require "lib.rule_utils"
local nkeys = require "table.nkeys"

local pairs = pairs
local concat = table.concat
local format = string.format
local write_string_to_file = file.write_string_to_file
local cjson_encode = cjson.encode

local _M = {}

local WEBSITES_PATH = config.CONF_PATH .. '/website.json'
local CERTIFICATE_PATH = config.CONF_PATH .. "/certificate.json"
local SITES_CONF_PATH = config.ZHONGKUI_PATH .. '/admin/conf/sites.conf'

-- nginx server
local NGINX_SERVER_CONFIG = [[
server {
%s
    server_name %s;

    charset utf-8;

%s
    location / {
        proxy_pass %s;
        proxy_set_header Host $host;
        proxy_set_header  X-Real-IP  $remote_addr;
        proxy_set_header  X-Forwarded-For $proxy_add_x_forwarded_for;
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

-- 生成站点配置文件
local function generate_nginx_config_file()
    local response = rule_utils.list_rules(WEBSITES_PATH)
    local sites = response.data
    local ngxConfig = ''

    if sites and nkeys(sites) > 0 then
        for _, site in pairs(sites) do
            local serverNames = site.serverNames
            local serverNameStr = concat(serverNames, ' ')
            local upstream = site.upstream
            local listenPorts = site.listenPorts
            local listenPortsStr = ''
            local sslCertConfigStr = ''
            local isSSL = nil

            if listenPorts then
                for _, p in pairs(listenPorts) do
                    local port = p.port
                    local sslStr = ''
                    if p.ssl == 'on' then
                        sslStr = ' ssl'
                        isSSL = true
                    end
                    listenPortsStr = listenPortsStr .. '    listen ' .. port .. sslStr .. ';\n'
                end
            end

            if isSSL then
                local certId = site.certId
                if certId then
                    local resp = rule_utils.get_rule(CERTIFICATE_PATH, certId)
                    if resp.code == 200 and resp.data then
                        local cert = resp.data
                        if cert then
                            local certPath = cert.certPath
                            local keyPath = cert.keyPath
                            sslCertConfigStr = format(SSL_CERT_CONFIG, certPath, keyPath)
                        end
                    end
                end
            end

            ngxConfig = ngxConfig .. format(NGINX_SERVER_CONFIG, listenPortsStr, serverNameStr, sslCertConfigStr, upstream)
        end
    end

    write_string_to_file(SITES_CONF_PATH, ngxConfig)
end

function _M.do_request()
    local response = {code = 200, data = {}, msg = ""}
    local uri = ngx.var.uri
    local reload = false

    if user.check_auth_token() == false then
        response.code = 401
        response.msg = 'User not logged in'
        ngx.status = 401
        ngx.say(cjson_encode(response))
        ngx.exit(401)
        return
    end

    if uri == "/sites/list" then
        -- 查询站点列表
        response = rule_utils.list_rules(WEBSITES_PATH)
    elseif uri == "/sites/save" then
        -- 修改或新增站点
        local newRule = rule_utils.get_rule_from_request()
        newRule.mode = 'protection'

        response = rule_utils.save_or_update_rule(WEBSITES_PATH, newRule)
        reload = true
    elseif uri == "/sites/remove" then
        -- 删除站点
        response = rule_utils.delete_rule(WEBSITES_PATH)
        reload = true
    end

    ngx.say(cjson_encode(response))

    -- 如果没有错误且需要重载配置文件则重载配置文件
    if response.code == 200 and reload == true then
        generate_nginx_config_file()
        config.reload_config_file()
    end
end

_M.do_request()

return _M
