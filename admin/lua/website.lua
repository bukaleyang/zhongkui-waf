-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

local cjson = require "cjson"
local config = require "config"
local user = require "user"
local file = require "file_utils"
local rule_utils = require "lib.rule_utils"
local site_config = require "lib.site_config"

local cjson_encode = cjson.encode
local read_file_to_string = file.read_file_to_string
local write_string_to_file_atomic = file.write_string_to_file_atomic

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
            newRule.mode = 'protection'
            response = rule_utils.save_or_update_rule(WEBSITES_PATH, newRule)
            need_reload = true
        end
    elseif uri == "/sites/remove" then
        -- 删除站点：片段在重载成功后归档，回滚时才能一起恢复
        local args = get_post_args()
        local site_id = args and args['id']

        old_sites_json = read_file_to_string(WEBSITES_PATH)
        response = rule_utils.delete_rule(WEBSITES_PATH, site_id)

        if response.code == 200 then
            archive_id = tonumber(site_id)
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
