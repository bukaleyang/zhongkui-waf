-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local cjson = require "cjson"
local config = require "config"
local user = require "user"
local ruleUtils = require "lib.ruleUtils"

local tonumber = tonumber

local get_site_config_file = config.get_site_config_file
local get_site_module_rule_file = config.get_site_module_rule_file
local update_site_config_file = config.update_site_config_file

local cjson_decode = cjson.decode
local cjson_encode = cjson.encode

local _M = {}

local MODULE_ID = 'cc'

function _M.doRequest()
    local response = {code = 200, data = {}, msg = ""}
    local uri = ngx.var.uri
    local reload = false

    if user.checkAuthToken() == false then
        response.code = 401
        response.msg = 'User not logged in'
        ngx.status = 401
        ngx.say(cjson_encode(response))
        ngx.exit(401)
        return
    end

    if uri == "/cc/config/get" then
        local args, err = ngx.req.get_uri_args()
        if args then
            local site_id = tostring(args['siteId'])
            local _, content = get_site_config_file(site_id)
            if content then
                local config_table = cjson_decode(content)
                local cc = config_table.cc
                response.data = cjson_encode(cc)
            else
                response.code = 500
                response.msg = 'no config file found'
            end
        else
            response.code = 500
            response.msg = err
        end
    elseif uri == "/cc/config/update" then
        -- 修改配置
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()
        if args then
            local site_id = tostring(args['siteId'])
            if site_id then
                local _, content = get_site_config_file(site_id)

                if content then
                    local config_table = cjson_decode(content)
                    local config_cc = config_table.cc
                    local cc_json = args.cc

                    if cc_json then
                        local cc = cjson_decode(cc_json)
                        cc.actionTimeout = tonumber(cc.actionTimeout);
                        cc.maxFailTimes = tonumber(cc.maxFailTimes);
                        cc.accesstokenTimeout = tonumber(cc.accesstokenTimeout);

                        for key, _ in pairs(config_cc) do
                            local v = cc[key]
                            if v then
                                config_cc[key] = v
                            end
                        end
                    end

                    local new_config_json = cjson_encode(config_table)
                    update_site_config_file(site_id, new_config_json)
                    reload = true
                else
                    response.code = 500
                    response.msg = 'no config file found'
                end
            else
                response.code = 500
                response.msg = 'param error'
            end
        else
            response.code = 500
            response.msg = err
        end
    elseif uri == "/cc/rule/list" then
        local args, err = ngx.req.get_uri_args()
        if args then
            local site_id = tostring(args['siteId'])
            if site_id then
                local file_path = get_site_module_rule_file(site_id, MODULE_ID)
                response = ruleUtils.listRules(file_path)
            else
                response.code = 500
                response.msg = 'param error'
            end
        else
            response.code = 500
            response.msg = err
        end
    elseif uri == "/cc/rule/save" then
        -- 修改或新增cc规则
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()
        if args then
            local site_id = tostring(args['siteId'])
            if site_id then
                local rule_new = ruleUtils.getRuleFromRequest()
                if rule_new then
                    rule_new.id = tonumber(rule_new.id)
                    rule_new.duration = tonumber(rule_new.duration)
                    rule_new.threshold = tonumber(rule_new.threshold)
                    rule_new.ipBlockTimeout = tonumber(rule_new.ipBlockTimeout)
                    rule_new.autoIpBlock = rule_new.autoIpBlock or 'off'
                    rule_new.attackType = 'cc-' .. rule_new.countType
                    rule_new.severityLevel = 'medium'

                    response = ruleUtils.save_or_update_site_rule(site_id, MODULE_ID, rule_new)
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
    elseif uri == "/cc/rule/state/update" then
        -- 修改cc规则状态
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()
        if args then
            local site_id = tostring(args['siteId'])
            local rule_id = tonumber(args['ruleId'])
            local state = tostring(args['state'])

            response = ruleUtils.update_site_rule_state(site_id, MODULE_ID, rule_id, state)
            if response and response.code == 200 then
                reload = true
            end
        else
            response.code = 500
            response.msg = err
        end
    elseif uri == "/cc/rule/remove" then
        -- 删除cc规则
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()
        if args then
            local site_id = tostring(args['siteId'])
            local rule_id = tonumber(args['ruleId'])

            response = ruleUtils.delete_site_rule(site_id, MODULE_ID, rule_id)
            if response and response.code == 200 then
                reload = true
            end
        else
            response.code = 500
            response.msg = err
        end
        reload = true
    end

    ngx.say(cjson_encode(response))

    -- 如果没有错误且需要重载配置文件则重载配置文件
    if (response.code == 200 or response.code == 0) and reload == true then
        config.reloadConfigFile()
    end
end

_M.doRequest()

return _M
