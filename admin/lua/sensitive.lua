-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local cjson = require "cjson"
local config = require "config"
local file = require "file_utils"
local user = require "user"
local rule_utils = require "lib.rule_utils"

local get_site_config_file = config.get_site_config_file
local get_site_module_rule_file = config.get_site_module_rule_file
local update_site_config_file = config.update_site_config_file

local read_file_to_string = file.read_file_to_string
local write_string_to_file = file.write_string_to_file
local is_file_exists = file.is_file_exists
local is_directory = file.is_directory
local mkdir = file.mkdir

local cjson_decode = cjson.decode
local cjson_encode = cjson.encode

local _M = {}

local MODULE_ID = 'sensitive'

local function get_site_sensitive_words_file(site_id)
    local rule_file = ''
    if site_id == '0' then
        rule_file = config.CONF_PATH .. '/global_rules/sensitiveWords'
    else
        rule_file = config.CONF_PATH .. '/sites/' .. site_id .. '/rules/sensitiveWords'
        if not is_file_exists(rule_file) then
            rule_file = config.CONF_PATH .. '/global_rules/sensitiveWords'
        end
    end

    return rule_file, read_file_to_string(rule_file)
end

local function update_site_sensitive_words_file(site_id, str)
    local rule_file = ''
    if site_id == '0' then
        rule_file = config.CONF_PATH .. '/global_rules/sensitiveWords'
    else
        local site_dir = config.CONF_PATH .. '/sites/' .. site_id
        if not is_directory(site_dir) then
            mkdir(site_dir)
        end

        local rules_dir = site_dir .. '/rules'
        if not is_directory(rules_dir) then
            mkdir(rules_dir)
        end

        rule_file = rules_dir .. '/sensitiveWords'
    end

    return write_string_to_file(rule_file, str)
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

    if uri == "/sensitive/config/get" then
        -- 查询配置信息
        local args, err = ngx.req.get_uri_args()
        if args then
            local site_id = tostring(args['siteId'])
            local _, content = get_site_config_file(site_id)
            if content then
                local config_table = cjson_decode(content)
                if config_table then
                    local _, sensitiveWords = get_site_sensitive_words_file(site_id)

                    local data = {}
                    data.sensitiveDataFilter = config_table.sensitiveDataFilter
                    data.senstiveWords = sensitiveWords

                    response.data = cjson_encode(data)
                end
            else
                response.code = 500
                response.msg = 'no config file found'
            end
        else
            response.code = 500
            response.msg = err
        end
    elseif uri == "/sensitive/config/state/update" then
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
                   config_table.sensitiveDataFilter.state = state
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
    elseif uri == "/sensitive/rule/list" then
        -- 查询敏感词过滤规则
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
    elseif uri == "/sensitive/rule/save" then
        -- 修改或新增敏感数据过滤规则
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()
        if args then
            local site_id = tostring(args['siteId'])
            if site_id then
                local rule_new = rule_utils.get_rule_from_request()
                if rule_new then
                    rule_new.id = tonumber(rule_new.id)
                    rule_new.action = 'coding'

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
    elseif uri == "/sensitive/rule/state/update" then
        -- 修改敏感词过滤规则开关状态
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
    elseif uri == "/sensitive/words/get" then
        -- 获取敏感词内容
        local args, err = ngx.req.get_uri_args()
        if args then
            local site_id = tostring(args['siteId'])
            local _, content = get_site_sensitive_words_file(site_id)

            response.data = {content = content}
        else
            response.code = 500
            response.msg = err
        end
    elseif uri == "/sensitive/words/update" then
        -- 修改敏感词
        local args = nil

        ngx.req.read_body()

        local body_raw = ngx.req.get_body_data()
        if not body_raw then
            local body_file = ngx.req.get_body_file()
            if body_file then
                body_raw = read_file_to_string(body_file)
            end
        end

        if body_raw and body_raw ~= "" then
            args = ngx.decode_args(body_raw, 0)
        end

        if args then
            local site_id = tostring(args['siteId'])
            local content = args['content']
            if content then
                update_site_sensitive_words_file(site_id, content)
                reload = true
            end
        end
    end

    ngx.say(cjson_encode(response))

    -- 如果没有错误且需要重载配置文件则重载配置文件
    if response.code == 200 and reload == true then
        config.reload_config_file()
    end
end

_M.do_request()

return _M
