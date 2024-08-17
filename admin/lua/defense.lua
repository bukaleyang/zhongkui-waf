-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local cjson = require "cjson"
local config = require "config"
local user = require "user"
local rule_utils = require "lib.rule_utils"

local get_site_config_file = config.get_site_config_file
local get_site_module_rule_file = config.get_site_module_rule_file
local update_site_config_file = config.update_site_config_file
local update_site_module_rule_file = config.update_site_module_rule_file

local tonumber = tonumber
local cjson_decode = cjson.decode
local cjson_encode = cjson.encode

local _M = {}


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

    if uri == "/defense/config/get" then
        local args, err = ngx.req.get_uri_args()
        if args then
            local site_id = tostring(args['siteId'])
            local _, content = get_site_config_file(site_id)
            response.data = content
        else
            response.code = 500
            response.msg = err
        end
    elseif uri == "/defense/config/update" then
        -- 修改配置
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()

        if args then
            local site_id = tostring(args['siteId'])
            local _, content = get_site_config_file(site_id)

            local config_table = cjson_decode(content)
            local waf = config_table.waf

            local state = args.state
            if state then
                waf.state = state
            end

            local mode = args.mode
            if mode then
                waf.mode = mode
            end

            local new_config_json = cjson_encode(config_table)
            update_site_config_file(site_id, new_config_json)
            reload = true
        else
            response.code = 500
            response.msg = err
        end
    elseif uri == "/defense/rule/list" then

        local args, err = ngx.req.get_uri_args()
        if args then
            local site_id = tostring(args['siteId'])
            local module_id = tostring(args['moduleId'])

            local file_path = get_site_module_rule_file(site_id, module_id)

            response = rule_utils.list_rules(file_path)
        else
            response.code = 500
            response.msg = err
        end
    elseif uri == "/defense/rule/state/update" then
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()
        if args then
            local site_id = tostring(args['siteId'])
            local module_id = tostring(args['moduleId'])
            local rule_id = tonumber(args['ruleId'])
            local state = tostring(args['state'])

            -- 没有规则id，则是模块开关
            if not rule_id then
                local _, content = get_site_config_file(site_id)
                if content then
                    local t = cjson_decode(content)
                    t[module_id]['state'] = state

                    local json = cjson_encode(t)
                    update_site_config_file(site_id, json)
                    reload = true
                end
            else
                local _, content = get_site_module_rule_file(site_id, module_id)
                if content then
                    local t = cjson_decode(content)
                    local rules = t.rules
                    for _, r in pairs(rules) do
                        if r.id == rule_id then
                            r.state = state
                            break
                        end
                    end

                    local json = cjson_encode(t)
                    update_site_module_rule_file(site_id, module_id, json)
                    reload = true
                end
            end
        else
            response.code = 500
            response.msg = err
        end
    elseif uri == "/defense/rule/save" then
        -- 修改或新增防御规则
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()
        if args then
            local site_id = tostring(args['siteId'])
            local module_id = tostring(args['moduleId'])
            if site_id and module_id then
                local rule_new = rule_utils.get_rule_from_request()
                if rule_new then
                    rule_new.id = tonumber(rule_new.id)
                    rule_new.state = rule_new.state or 'off'
                    rule_new.action = rule_new.action or 'deny'
                    rule_new.attackType = rule_new.attackType or 'unknown'
                    rule_new.severityLevel = 'medium'

                    response = rule_utils.save_or_update_site_rule(site_id, module_id, rule_new)
                    reload = true
                else
                    response.code = 500
                    response.msg = 'param error'
                end
            else
                response.code = 500
                response.msg = 'param error'
            end
        else
            response.code = 500
            response.msg = err
        end
    elseif uri == "/defense/rule/remove" then
        -- 删除防御规则
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()
        if args then
            local site_id = tostring(args['siteId'])
            local rule_id = tonumber(args['ruleId'])
            local module_id = tostring(args['moduleId'])
            if site_id and rule_id and module_id then
                response = rule_utils.delete_site_rule(site_id, module_id, rule_id)
            else
                response.code = 500
                response.msg = 'param error'
            end
        else
            response.code = 500
            response.msg = err
        end
    end

    ngx.say(cjson_encode(response))

    -- 如果没有错误且需要重载配置文件则重载配置文件
    if (response.code == 200 or response.code == 0) and reload == true then
        config.reload_config_file()
    end
end

_M.do_request()

return _M
