-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local cjson = require "cjson"
local config = require "config"
local file_utils = require "file_utils"
local user = require "user"
local rule_utils = require "lib.rule_utils"

local tonumber = tonumber
local insert = table.insert

local cjson_decode = cjson.decode
local cjson_encode = cjson.encode

local _M = {}

local IP_GROUP_PATH = config.CONF_PATH .. '/ipgroup.json'
local ACL_PATH = config.CONF_PATH .. '/global_rules/acl.json'

function _M.do_request()
    local response = {code = 200, data = {}, msg = ""}
    local uri = ngx.var.uri
    local reload = false

    if user.check_auth_token() == false then
        response.code = 401
        response.msg = 'User not logged in'
        ngx.status = 401
        ngx.say(cjson_encode(response))
        return ngx.exit(401)
    end

    if uri == "/common/ipgroups/list" then
        -- ip组列表
        response = rule_utils.list_rules(IP_GROUP_PATH)
    elseif uri == "/common/ipgroups/listnames" then
        local json = file_utils.read_file_to_string(IP_GROUP_PATH)
        if json then
            local ruleTable = cjson_decode(json)
            local rules = ruleTable.rules

            local groups = {}

            if rules then
                for _, r in pairs(rules) do
                    local group = {id = r.id, groupName = r.groupName }
                    insert(groups, group)
                end
            end

            response.data = groups
        end
    elseif uri == "/common/ipgroups/get" then
        -- ip组内容
        local args, err = ngx.req.get_uri_args()
        if args then
            local id = tonumber(args['id'])
            if id then
                response = rule_utils.get_rule(IP_GROUP_PATH, id)
            end
        else
            response.code = 500
            response.msg = err
            ngx.log(ngx.ERR, err)
        end
    elseif uri == "/common/ipgroups/update" then
        -- 修改ip组内容
        local newRule = rule_utils.get_rule_from_request()
        if newRule then
            newRule.id = tonumber(newRule.id)
            local ips = newRule.ips

            if not ips or #ips == 0 then
                response.code = 500
                response.msg = 'param content is empty'
            end

            response = rule_utils.save_or_update_rule(IP_GROUP_PATH, newRule)
            reload = true
        else
            response.code = 500
            response.msg = 'param is empty'
        end
    elseif uri == "/common/ipgroups/remove" then
        -- 删除IP组
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()

        if args then
            local id = tonumber(args['id'])
            if id then
                local flag = false
                local json = file_utils.read_file_to_string(ACL_PATH)
                if json then
                    local ruleTable = cjson_decode(json)
                    local rules = ruleTable.rules

                    if rules then
                        for _, r in pairs(rules) do
                            local conditions = r.conditions or {}
                            for _, c in pairs(conditions) do
                                if c.ipGroupId == id then
                                    flag = true
                                    break
                                end
                            end

                            if flag then
                                break
                            end
                        end
                    end
                end

                if flag then
                    response.code = 500
                    response.msg = '该IP组被其他规则引用，不能删除'
                else
                    response = rule_utils.delete_rule(IP_GROUP_PATH)
                    reload = true
                end
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
