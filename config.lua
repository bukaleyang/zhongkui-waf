-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local cjson = require "cjson"
local file_utils = require "file_utils"
local ip_utils = require "ip_utils"
local constants = require "constants"
local stringutf8 = require "stringutf8"
local nkeys = require "table.nkeys"
local ffi = require "ffi"
local ipmatcher = require "resty.ipmatcher"

local read_rule = file_utils.read_rule
local read_file_to_string = file_utils.read_file_to_string
local read_file_to_table = file_utils.read_file_to_table
local write_string_to_file = file_utils.write_string_to_file
local is_file_exists = file_utils.is_file_exists
local is_directory = file_utils.is_directory
local mkdir = file_utils.mkdir

local sub = string.sub
local default_if_blank = stringutf8.default_if_blank

local cjson_decode = cjson.decode
local cjson_encode = cjson.encode

local pairs = pairs
local ipairs = ipairs
local tonumber = tonumber

local _M = {}

local config = {system = {}, global = {}}

_M.ipgroups = {}

-- Returns true if the global config option is "on",otherwise false
function _M.is_global_option_on(option)
    return config.global.config[option].state == "on"
end

function _M.is_system_option_on(option)
    return config.system[option].state == "on"
end

function _M.is_site_option_on(option)
    local server_name = ngx.ctx.server_name or default_if_blank(ngx.var.server_name, 'unknown')
    if not config[server_name] then
        return _M.is_global_option_on(option)
    end
    return config[server_name].config[option].state == "on"
end

function _M.get_system_config(option)
    if option then
        return config.system[option]
    end
    return config.system
end

function _M.get_global_config(option)
    if option then
        return config.global.config[option]
    end
    return config.global.config
end

function _M.get_site_config(option)
    local server_name = ngx.ctx.server_name or default_if_blank(ngx.var.server_name, 'unknown')
    if not config[server_name] then
        return _M.get_global_config(option)
    end
    if option then
        return config[server_name].config[option]
    end
    return config[server_name].config
end

function _M.get_global_security_modules(module)
    if module then
        return config.global.security_modules[module]
    end
    return config.global.security_modules
end

function _M.get_site_security_modules(module)
    local server_name = ngx.ctx.server_name or default_if_blank(ngx.var.server_name, 'unknown')
    if not config[server_name] then
        return _M.get_global_security_modules(module)
    end
    if module then
        return config[server_name].security_modules[module]
    end
    return config[server_name].security_modules
end

function _M.get_site_config_file(site_id)
    local config_file = ''

    if site_id == '0' then
        config_file = _M.CONF_PATH .. '/global.json'
    else
        config_file = _M.CONF_PATH .. '/sites/' .. site_id .. '/config.json'
        if not is_file_exists(config_file) then
            config_file = _M.CONF_PATH .. '/global.json'
        end
    end
    return config_file, read_file_to_string(config_file)
end

function _M.update_site_config_file(site_id, str)
    local config_file = ''

    if site_id == '0' then
        config_file = _M.CONF_PATH .. '/global.json'
    else
        local site_dir = _M.CONF_PATH .. '/sites/' .. site_id
        config_file = site_dir .. '/config.json'
        if not is_directory(site_dir) then
            mkdir(site_dir)
        end
    end
    return write_string_to_file(config_file, str)
end

function _M.get_site_module_rule_file(site_id, module_id)
    local file_name = module_id .. '.json'
    local rule_file = ''

    if site_id == '0' then
        rule_file = _M.CONF_PATH .. '/global_rules/' .. file_name
    else
        rule_file = _M.CONF_PATH .. '/sites/' .. site_id .. '/rules/' .. file_name
        if not is_file_exists(rule_file) then
            rule_file = _M.CONF_PATH .. '/global_rules/' .. file_name
        end
    end

    return rule_file, read_file_to_string(rule_file)
end

function _M.update_site_module_rule_file(site_id, module_id, str)
    local file_name = module_id .. '.json'
    local rule_file = ''

    if site_id == '0' then
        rule_file = _M.CONF_PATH .. '/global_rules/' .. file_name
    else
        local site_dir = _M.CONF_PATH .. '/sites/' .. site_id
        if not is_directory(site_dir) then
            mkdir(site_dir)
        end

        local rules_dir = site_dir .. '/rules'
        if not is_directory(rules_dir) then
            mkdir(rules_dir)
        end

        rule_file = rules_dir .. '/' .. file_name
    end

    return write_string_to_file(rule_file, str)
end

local function add_ip_group(group, ips)
    if ips and nkeys(ips) > 0 then
        local matcher, err = ipmatcher.new(ips)
        if not matcher then
            ngx.log(ngx.ERR, 'error to add ip group ' .. group, err)
            return
        end
        _M.ipgroups[group] = matcher
    end
end

function _M.get_config_table()
    return config
end

local function load_security_modules(rulePath, site_config)
    local security_modules = {}
    security_modules.blackUrl = read_rule(rulePath, "blackUrl")
    security_modules.args = read_rule(rulePath, "args")
    security_modules.whiteUrl = read_rule(rulePath, "whiteUrl")
    security_modules.post = read_rule(rulePath, "post")
    security_modules.cookie = read_rule(rulePath, "cookie")
    security_modules.headers = read_rule(rulePath, "headers")
    security_modules.httpMethod = read_rule(rulePath, "httpMethod")
    security_modules.fileExt = read_rule(rulePath, "fileExt")
    security_modules.cc = read_rule(rulePath, "cc")
    security_modules.acl = read_rule(rulePath, "acl")
    security_modules.sensitive = read_rule(rulePath, "sensitive")
    security_modules["user-agent"] = read_rule(rulePath, "user-agent")

    security_modules.sqli = { moduleName = "SQL注入检测", rules = {{ attackType = "sqli", rule = "sqli", action = "DENY", severityLevel="high" }}}
    security_modules.xss = { moduleName = "XSS检测",  rules = {{ attackType = "xss", rule = "xss", action = "DENY", severityLevel="low" }}}
    security_modules.whiteIp = { moduleName = "IP白名单检测", rules = {{ attackType = "whiteip", rule = "whiteip", action = "ALLOW", severityLevel="low" }}}
    security_modules.blackIp = { moduleName = "IP黑名单检测", rules = {{ attackType = "blackip", rule = "blackip", action = "DENY", severityLevel="high" }}}

    local trap = site_config.bot.trap
    local rule_trap = { attackType = "bot_trap", rule = "bot_trap", severityLevel="low" }
    rule_trap.action = trap.action
    rule_trap.autoIpBlock = trap.autoIpBlock
    rule_trap.ipBlockExpireInSeconds = tonumber(trap.ipBlockExpireInSeconds)
    rule_trap.uri = trap.uri
    security_modules.botTrap = { moduleName = "Bot识别",  rules = {rule_trap}}

    local captcha = site_config.bot.captcha
    local rule_captcha = { attackType = "captcha", rule = "captcha", severityLevel="low" }
    rule_captcha.autoIpBlock = captcha.autoIpBlock
    rule_captcha.ipBlockExpireInSeconds = tonumber(captcha.ipBlockExpireInSeconds)
    rule_captcha.verifyInSeconds = tonumber(captcha.verifyInSeconds)
    rule_captcha.maxFailTimes = tonumber(captcha.maxFailTimes)
    rule_captcha.expireInSeconds = tonumber(captcha.expireInSeconds)
    rule_captcha.type = captcha.type
    security_modules.captcha = { moduleName = "人机验证",  rules = {rule_captcha}}

    return security_modules
end

local function storage_security_modules(server_name, security_modules)
    local json = cjson_encode(security_modules)
    local dict_config = ngx.shared.dict_config
    dict_config:set(server_name, json)
end

local function load_system_config()
    local system_path = _M.CONF_PATH .. '/system.json'
    local json = read_file_to_string(system_path)
    local system = {}
    if json then
        system = cjson_decode(json)
    end

    local log_path = system.attackLog.logPath
    if log_path and #log_path > 0 then
        local last = sub(log_path, -1)
        if last ~= "/" and last ~= "\\" then
            log_path = log_path .. "/"
        end
    end

    _M.LOG_PATH = log_path or _M.ZHONGKUI_PATH .. "/logs/hack/"
    system.attackLog.logPath = _M.LOG_PATH
    system.html = read_file_to_string(_M.ZHONGKUI_PATH .. "/html/redirect.html")
    system.challenge_html = read_file_to_string(_M.ZHONGKUI_PATH .. "/html/challenge.html")

    config.system = system
end

local function load_global_config()
    local global_path = _M.CONF_PATH .. '/global.json'
    local global_config = {}
    local security_modules = {}
    local json = read_file_to_string(global_path)

    if json then
        global_config = cjson_decode(json)
        if global_config.waf.state == 'on' then
            security_modules = load_security_modules(_M.CONF_PATH .. '/global_rules/', global_config)
            storage_security_modules('global', security_modules)
        end
    end

    config.global = {config = global_config, security_modules = security_modules}

    local ip_blacklist_cidr, ip_blacklist = ip_utils.filter_ip_list(read_file_to_table(_M.CONF_PATH .. "/global_rules/ipBlackList"))
    local ip_whitelist = read_file_to_table(_M.CONF_PATH .. "/global_rules/ipWhiteList")
    add_ip_group(constants.KEY_IP_GROUPS_BLACKLIST, ip_blacklist_cidr)
    add_ip_group(constants.KEY_IP_GROUPS_WHITELIST, ip_whitelist)
end

local function load_site_config()
    local website_path = _M.CONF_PATH .. '/website.json'
    local json = read_file_to_string(website_path)
    if json then
        local global = config.global
        local global_config = global.config
        local t = cjson_decode(json)
        local sites = t.rules

        if sites then
            for _, site in pairs(sites) do
                local site_config = {}

                local id = site.id
                local site_dir = _M.CONF_PATH .. '/sites/' .. tostring(id)
                local config_file = site_dir .. '/config.json'
                local config_str = read_file_to_string(config_file)
                if config_str then
                    site_config = cjson_decode(config_str)
                end

                -- 站点有独立设置则使用独立设置，否则使用全局设置
                for k, v in pairs(global_config) do
                    site_config[k] = site_config[k] or v
                end

                -- waf全局关闭则关闭站点waf
                if global_config.waf.state == 'off' then
                    site_config.waf.state = 'off'
                end

                local security_modules = load_security_modules(site_dir .. '/rules/', site_config)

                -- 站点有独立安全模块设置则使用独立设置，否则使用全局设置
                for k, v in pairs(global.security_modules) do
                    security_modules[k] = security_modules[k] or v
                end

                local serverNames = site.serverNames
                for _, server_name in pairs(serverNames) do
                    config[server_name] = {config = site_config, security_modules = security_modules}
                    storage_security_modules(server_name, security_modules)
                end
            end
        end
    end
end

local function load_ip_groups()
    local path = _M.CONF_PATH .. '/ipgroup.json'
    local json = read_file_to_string(path)
    if json then
        local table_rule = cjson_decode(json)
        local groups = table_rule.rules

        if groups then
            for _, g in pairs(groups) do
                add_ip_group(tonumber(g.id), g.ips)
            end
        end
    end
end

-- 加载配置文件
function _M.load_config_file()
    load_system_config()
    load_global_config()
    load_site_config()
    load_ip_groups()
end

-- 获取nginx安装目录
local function get_nginx_command_path()
    local path = ''
    -- 获取当前 Lua 脚本的文件路径
    local script_path = debug.getinfo(1, "S").source:sub(2)
    -- 获取 OpenResty 安装目录（假设 OpenResty 在 "/usr/local/openresty" 目录下）
    local openresty_path = script_path:match("(.*/openresty/)")
    if openresty_path then
        path = openresty_path .. 'nginx/sbin/'
    end
    return path
end

-- 是否Linux系统
local function is_linux()
    return ffi.os == "Linux"
end

-- 重新加载nginx配置
function _M.reload_nginx()
    -- Nginx重新加载配置文件的系统命令
    local command = get_nginx_command_path() .. "nginx -s reload"
    if is_linux() then
        command = "sudo " .. command
    end

    local success = os.execute(command)
    if success then
        ngx.log(ngx.INFO, "nginx configuration has been successfully reloaded.")
    else
        ngx.log(ngx.ERR, "failed to reload Nginx configuration.")
    end
end

-- 如果配置文件正确，则重载nginx
function _M.reload_config_file()
    _M.reload_nginx()
end

return _M
