-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local cjson = require "cjson"
local config = require "config"
local user = require "user"
local rule_utils = require "lib.rule_utils"

local tonumber = tonumber
local gsub = string.gsub

local get_site_config_file = config.get_site_config_file
local get_site_module_rule_file = config.get_site_module_rule_file
local update_site_config_file = config.update_site_config_file

local cjson_decode = cjson.decode
local cjson_encode = cjson.encode

local _M = {}

local MODULE_ID = 'user-agent'

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

    if uri == "/bot/config/get" then
        local args, err = ngx.req.get_uri_args()

        if args then
            local site_id = tostring(args['siteId'])
            local _, content = get_site_config_file(site_id)
            if content then
                local config_table = cjson_decode(content)
                local bot = config_table.bot
                response.data = cjson_encode(bot)
            else
                response.code = 500
                response.msg = 'no config file found'
            end
        else
            response.code = 500
            response.msg = err
        end
    elseif uri == "/bot/config/state/update" then
        -- 修改配置
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()
        if args then
           local site_id = tostring(args['siteId'])
           local state = args.state
           local _, content = get_site_config_file(site_id)

           if state and content then
               local config_table = cjson_decode(content)
               if config_table then
                   config_table.bot.state = state
                   local new_config_json = cjson_encode(config_table)
                   update_site_config_file(site_id, new_config_json)
                   reload = true
               end
           else
               response.code = 500
               response.msg = 'param error'
           end
        else
            response.code = 500
            response.msg = err
        end
    elseif uri == "/bot/config/trap/update" then
        -- 修改配置
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()

        if args then
            local site_id = tostring(args['siteId'])
            if site_id then
                local _, content = get_site_config_file(site_id)

                if content then
                    local config_table = cjson_decode(content)
                    local config_bot = config_table.bot
                    local config_trap = config_bot.trap
                    local trap_json = args.trap

                    if trap_json then
                        local trap = cjson_decode(trap_json)
                        if trap then
                            trap.ipBlockExpireInSeconds = tonumber(trap.ipBlockExpireInSeconds)

                            for key, _ in pairs(config_trap) do
                                local v = trap[key]
                                if v then
                                    config_trap[key] = v
                                end
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
    elseif uri == "/bot/config/captcha/update" then
        -- 修改配置
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()
        if args then
            local site_id = tostring(args['siteId'])
            if site_id then
                local _, content = get_site_config_file(site_id)

                if content then
                    local config_table = cjson_decode(content)
                    local config_bot = config_table.bot
                    local config_captcha = config_bot.captcha
                    local captcha_json = args.captcha

                    if captcha_json then
                        local captcha = cjson_decode(captcha_json)
                        if captcha then
                            captcha.verifyInSeconds = 300
                            captcha.maxFailTimes = tonumber(captcha.maxFailTimes) or 3
                            captcha.expireInSeconds = tonumber(captcha.expireInSeconds) or 1800
                            captcha.ipBlockExpireInSeconds = tonumber(captcha.ipBlockExpireInSeconds) or 1800

                            for key, _ in pairs(config_captcha) do
                                local v = captcha[key]
                                if v then
                                    config_captcha[key] = v
                                end
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
    elseif uri == "/bot/ua/rule/list" then
        local args, err = ngx.req.get_uri_args()

        if args then
            local site_id = tostring(args['siteId'])

            if site_id then
                local file_path = get_site_module_rule_file(site_id, MODULE_ID)
                response = rule_utils.list_rules(file_path)
            else
                response.code = 500
                response.msg = 'param error'
            end
        else
            response.code = 500
            response.msg = err
        end
    elseif uri == "/bot/ua/rule/save" then
        -- 修改或新增ua规则
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()

        if args then
            local site_id = tostring(args['siteId'])
            if site_id then
                local rule_new = rule_utils.get_rule_from_request()
                if rule_new then
                    rule_new.id = tonumber(rule_new.id)
                    rule_new.ipBlockExpireInSeconds = tonumber(rule_new.ipBlockExpireInSeconds)
                    rule_new.autoIpBlock = rule_new.autoIpBlock or 'off'
                    rule_new.attackType = 'bot'
                    rule_new.severityLevel = 'low'

                    local rule = rule_new.rule
                    if rule then
                        rule = gsub(rule, '\n', '|')
                    end
                    rule_new.rule = rule
                    response = rule_utils.save_or_update_site_rule(site_id, MODULE_ID, rule_new)
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
    elseif uri == "/bot/ua/rule/state/update" then
        -- 修改ua规则状态
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()

        if args then
            local site_id = tostring(args['siteId'])
            local rule_id = tonumber(args['ruleId'])
            local state = tostring(args['state'])

            response = rule_utils.update_site_rule_state(site_id, MODULE_ID, rule_id, state)
            if response and response.code == 200 then
                reload = true
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
