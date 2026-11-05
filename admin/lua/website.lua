-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

local cjson = require "cjson"
local config = require "config"
local user = require "user"
local file = require "file_utils"
local rule_utils = require "lib.rule_utils"
local site_config = require "lib.site_config"

local cjson_encode = cjson.encode
local cjson_decode = cjson.decode
local read_file_to_string = file.read_file_to_string
local write_string_to_file_atomic = file.write_string_to_file_atomic
local format = string.format
local match = string.match
local gsub = string.gsub
local concat = table.concat

local _M = {}

local WEBSITES_PATH = config.CONF_PATH .. '/website.json'

-- 站点写操作串行化，避免并发覆盖回滚快照
local CONFIG_LOCK_KEY = 'site:config'
local CONFIG_LOCK_TTL = 60
local lock_counter = 0

local function acquire_config_lock()
    local dict = ngx.shared.dict_locks
    if not dict then
        -- 共享字典缺失时退化为不加锁
        return nil, true
    end

    lock_counter = lock_counter + 1
    local token = tostring(ngx.worker.pid()) .. ':' .. tostring(ngx.now()) .. ':' .. tostring(lock_counter)
    local ok = dict:add(CONFIG_LOCK_KEY, token, CONFIG_LOCK_TTL)
    if ok ~= true then
        return nil, false
    end

    return token, false
end

local function release_config_lock(token)
    local dict = ngx.shared.dict_locks
    if dict and token and dict:get(CONFIG_LOCK_KEY) == token then
        dict:delete(CONFIG_LOCK_KEY)
    end
end

-- body 落到临时文件时 get_post_args() 会失败，这里手动读取
local function get_post_args()
    ngx.req.read_body()

    local body = ngx.req.get_body_data()
    if not body then
        local body_file = ngx.req.get_body_file()
        if body_file then
            body = read_file_to_string(body_file)
        end
    end

    return body and ngx.decode_args(body, 0) or nil
end

-- 端口必须是 1-65535 的整数，非法值会生成加载不了的配置
local function parse_port(value)
    local text = tostring(value == nil and '' or value)
    if not match(text, '^%d+$') then
        return nil
    end

    local port = tonumber(text)
    if not port or port < 1 or port > 65535 then
        return nil
    end

    return port
end

-- 站点结构校验：任何一项不合法都会生成死站（80 返回 404 且 443 未监听），保存前拦住
local function validate_site(rule)
    if type(rule) ~= 'table' then
        return '参数错误'
    end

    if type(rule.serverNames) ~= 'table' or #rule.serverNames == 0 then
        return '请至少配置一个域名'
    end

    for _, name in ipairs(rule.serverNames) do
        if type(name) ~= 'string' or gsub(name, '%s+', '') == '' then
            return '域名不能为空'
        end
    end

    if type(rule.upstream) ~= 'string' or not match(rule.upstream, '^https?://%S+$') then
        return '后端地址必须以 http:// 或 https:// 开头'
    end

    local ports = rule.listenPorts
    if type(ports) ~= 'table' or #ports == 0 then
        return '请至少配置一个监听端口'
    end

    local seen = {}
    local hasSslPort = false
    for _, item in ipairs(ports) do
        local port = type(item) == 'table' and parse_port(item.port)
        if not port then
            return '监听端口必须是 1-65535 之间的数字'
        end

        if seen[port] then
            return format('监听端口 %d 重复，请删除多余的一项', port)
        end

        seen[port] = true
        -- 归一化，避免 "080" 被生成阶段当成非 80 的明文端口
        item.port = tostring(port)

        local isSSL = (item.ssl == 'on' or item.ssl == true)
        if isSSL and port == 80 then
            return '80 端口由系统统一管理，不能启用 SSL'
        end

        hasSslPort = hasSslPort or isSSL
    end

    -- 证书不可用时生成阶段会跳过 HTTPS 端口，站点将完全不可访问
    if hasSslPort and not site_config.is_cert_usable(rule.certId) then
        return 'HTTPS 端口需要绑定可用证书，请重新选择证书'
    end

    if (rule.forceHttps == 'on' or rule.forceHttps == true) and not hasSslPort then
        return '开启强制 HTTPS 前请先配置 HTTPS 端口并绑定证书'
    end

    return nil
end

-- 读取站点原值（整对象替换的保存方式下用来补齐缺省字段/记审计日志）
local function get_old_site(old_json, site_id)
    site_id = tonumber(site_id)
    if not site_id or not old_json then
        return nil
    end

    local ok, data = pcall(cjson_decode, old_json)
    if not ok or type(data) ~= 'table' or type(data.rules) ~= 'table' then
        return nil
    end

    for _, item in pairs(data.rules) do
        if tonumber(item.id) == site_id then
            return item
        end
    end

    return nil
end

-- 请求未带 forceHttps 时沿用原值，避免第三方调用保存接口时把开关静默清空
local function inherit_force_https(old_json, rule)
    if rule.forceHttps ~= nil then
        return
    end

    local old_site = get_old_site(old_json, rule.id)
    if old_site then
        rule.forceHttps = old_site.forceHttps
    end
end

-- 监听端口的可读描述，用于审计日志
local function ports_text(ports)
    local items = {}
    for _, item in ipairs(type(ports) == 'table' and ports or {}) do
        if type(item) == 'table' then
            local ssl = (item.ssl == 'on' or item.ssl == true) and '/ssl' or ''
            items[#items + 1] = tostring(item.port) .. ssl
        end
    end

    return concat(items, ',')
end

-- 生成、校验并重载
local function regenerate_and_reload()
    local generated, gen_err = site_config.generate()
    if not generated then
        return false, '生成站点配置失败: ' .. tostring(gen_err), nil, false
    end

    local passed, detail = config.test_nginx_config_detail()
    if not passed then
        return false, 'nginx 配置校验失败', detail, false
    end

    -- 已经做过 -t，跳过 reload_nginx() 内部的重复校验
    local reloaded, reload_err = config.reload_config_file(true)
    if not reloaded then
        return false, 'nginx 重载失败: ' .. tostring(reload_err), nil, true
    end

    return true
end

-- 失败时还原 website.json 与 sites.conf
local function rollback_sites(old_json, reload_failed)
    if old_json then
        local ok, err = write_string_to_file_atomic(WEBSITES_PATH, old_json)
        if not ok then
            ngx.log(ngx.ERR, "failed to restore ", WEBSITES_PATH, ": ", tostring(err))
        end
    end

    local generated, gen_err = site_config.generate()
    if not generated then
        ngx.log(ngx.ERR, "failed to regenerate sites.conf after rollback: ", tostring(gen_err))
    end

    -- reload 失败时运行态不确定，恢复文件后再重载一次；-t 失败时 nginx 仍跑旧配置
    if reload_failed then
        local reloaded, reload_err = config.reload_config_file(true)
        if not reloaded then
            ngx.log(ngx.ERR, "failed to reload after rollback: ", tostring(reload_err))
        end
    end
end

function _M.do_request()
    local response = {code = 200, data = {}, msg = ""}
    local uri = ngx.var.uri
    local need_reload = false
    local old_sites_json = nil
    local archive_id = nil

    if user.check_auth_token() == false then
        response.code = 401
        response.msg = 'User not logged in'
        ngx.status = 401
        ngx.say(cjson_encode(response))
        ngx.exit(401)
        return
    end

    -- 写操作要求 POST，避免 GET 被 CSRF 触发
    if uri ~= "/sites/list" and uri ~= "/sites/custom/get" then
        if ngx.req.get_method() ~= 'POST' then
            response.code = 405
            response.msg = 'Method Not Allowed'
            ngx.status = 405
            ngx.say(cjson_encode(response))
            return
        end

        -- 跨站表单无法伪造 XHR 自动携带的请求头
        if ngx.var.http_x_requested_with ~= 'XMLHttpRequest' then
            response.code = 403
            response.msg = '请求来源校验失败，请刷新页面后重试'
            ngx.status = 403
            ngx.say(cjson_encode(response))
            return
        end
    end

    -- 同一时间只允许一个配置变更流程
    local lock_token = nil
    if uri ~= "/sites/list" and uri ~= "/sites/custom/get" then
        local lock_unavailable
        lock_token, lock_unavailable = acquire_config_lock()
        if not lock_token and not lock_unavailable then
            response.code = 409
            response.msg = '正在应用其他配置变更，请稍后再试'
            ngx.say(cjson_encode(response))
            return
        end
    end

    if uri == "/sites/list" then
        -- 查询站点列表
        response = rule_utils.list_rules(WEBSITES_PATH)
    elseif uri == "/sites/save" then
        -- 修改或新增站点
        old_sites_json = read_file_to_string(WEBSITES_PATH)
        local newRule = rule_utils.get_rule_from_request()

        if not newRule then
            response.code = 400
            response.msg = '参数错误'
        else
            -- 整对象替换：请求未携带 forceHttps 时沿用原值，避免开关被静默清空
            inherit_force_https(old_sites_json, newRule)

            local invalid = validate_site(newRule)
            if invalid then
                response.code = 400
                response.msg = invalid
            else
                newRule.mode = 'protection'
                response = rule_utils.save_or_update_rule(WEBSITES_PATH, newRule)

                if response.code == 200 then
                    -- 强制 HTTPS 属安全相关配置，变更留审计日志
                    local old_site = get_old_site(old_sites_json, newRule.id)
                    ngx.log(ngx.INFO, format('site save: id=%s names=%s ports=%s forceHttps=%s->%s certId=%s',
                        tostring(newRule.id), concat(newRule.serverNames or {}, ','),
                        ports_text(newRule.listenPorts), tostring(old_site and old_site.forceHttps),
                        tostring(newRule.forceHttps), tostring(newRule.certId)))
                end

                need_reload = true
            end
        end
    elseif uri == "/sites/remove" then
        -- 删除站点：片段在重载成功后归档，回滚时才能一起恢复
        local args = get_post_args()
        local site_id = args and args['id']

        old_sites_json = read_file_to_string(WEBSITES_PATH)
        response = rule_utils.delete_rule(WEBSITES_PATH, site_id)

        if response.code == 200 then
            archive_id = tonumber(site_id)
            local removed = get_old_site(old_sites_json, site_id)
            ngx.log(ngx.INFO, format('site remove: id=%s names=%s',
                tostring(site_id), concat(removed and removed.serverNames or {}, ',')))
        end

        need_reload = true
    elseif uri == "/sites/custom/get" then
        -- 读取自定义片段
        local args = ngx.req.get_uri_args()
        local content, err = site_config.get_site_fragment(args and args['id'])

        if content then
            response.data = {content = content}
        else
            response.code = 400
            response.msg = err or '读取自定义配置失败'
        end
    elseif uri == "/sites/custom/save" then
        -- 保存自定义片段（内部完成校验、回滚与重载）
        local args = get_post_args()
        response = site_config.save_site_fragment(args and args['id'], args and args['content'])
    elseif uri == "/sites/reload" then
        -- 手工修改片段后重新生成并重载
        response = site_config.reload_site_config()
    end

    -- 先完成生成/校验/重载，再输出响应
    if response.code == 200 and need_reload then
        local ok, msg, detail, reload_failed = regenerate_and_reload()
        if ok then
            if archive_id then
                local archived = site_config.archive_site_fragment(archive_id)
                if not archived then
                    response.msg = '站点已删除，但自定义配置清理失败，请联系管理员检查文件权限'
                end
            end

            -- 生成告警（端口被跳过、强制 HTTPS 未生效）必须回显，否则站点会静默降级
            response = site_config.append_warnings(response)
        else
            rollback_sites(old_sites_json, reload_failed)
            response.code = 500
            response.msg = msg
            response.detail = detail
        end
    end

    -- 先释放锁再输出响应
    release_config_lock(lock_token)

    ngx.say(cjson_encode(response))
end

_M.do_request()

return _M
