local cjson = require "cjson"
local config = require "config"
local file = require "file"
local user = require "user"
local ruleUtils = require "lib.ruleUtils"
local nkeys = require "table.nkeys"

local pairs = pairs
local concat = table.concat
local format = string.format

local _M = {}

local WEBSITES_PATH = config.rulePath .. 'website.json'
local SITES_CONF_PATH = config.ZHONGKUI_PATH .. '/conf/sites.conf'

-- nginx server
local NGINX_SERVER_CONFIG = [[
server {
%s
    server_name %s;

    charset utf-8;

%s
    location / {
        proxy_pass %s;
        proxy_set_header  X-Real-IP  $remote_addr;
        proxy_set_header  X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
]]

-- ssl certificate
local SSL_CERT_CONFIG = [[
    # ssl_certificate      cert.pem;
    # ssl_certificate_key  cert.key;

    # ssl_session_cache    shared:SSL:1m;
    # ssl_session_timeout  5m;

    # ssl_ciphers  HIGH:!aNULL:!MD5;
    # ssl_prefer_server_ciphers  on;
]]

-- 生成站点配置文件
function _M.generateNginxConfigFile()
    local response = ruleUtils.listRules(WEBSITES_PATH)
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

            if listenPorts then
                for _, p in pairs(listenPorts) do
                    local port = p.port
                    local sslStr = ''
                    if p.ssl == 'on' then
                        sslStr = ' ssl'
                        sslCertConfigStr = SSL_CERT_CONFIG
                    end
                    listenPortsStr = listenPortsStr .. '    listen ' .. port .. sslStr .. ';\n'
                end
            end

            ngxConfig = ngxConfig .. format(NGINX_SERVER_CONFIG, listenPortsStr, serverNameStr, sslCertConfigStr, upstream)
        end
    end

    file.writeStringToFile(SITES_CONF_PATH, ngxConfig)
end

function _M.doRequest()
    local response = {code = 200, data = {}, msg = ""}
    local uri = ngx.var.uri
    local reload = false

    if user.checkAuthToken() == false then
        response.code = 401
        response.msg = 'User not logged in'
        ngx.status = 401
        ngx.say(cjson.encode(response))
        ngx.exit(401)
        return
    end

    if uri == "/sites/list" then
        -- 查询站点列表
        response = ruleUtils.listRules(WEBSITES_PATH)
    elseif uri == "/sites/save" then
        -- 修改或新增站点
        local newRule = ruleUtils.getRuleFromRequest()
        newRule.mode = 'protection'

        response = ruleUtils.saveOrUpdateRule(WEBSITES_PATH, newRule)
        reload = true
    elseif uri == "/sites/remove" then
        -- 删除站点
        response = ruleUtils.deleteRule(WEBSITES_PATH)
        reload = true
    end

    ngx.say(cjson.encode(response))

    -- 如果没有错误且需要重载配置文件则重载配置文件
    if response.code == 200 and reload == true then
        _M.generateNginxConfigFile()
        config.reloadConfigFile()
    end
end

_M.doRequest()

return _M
