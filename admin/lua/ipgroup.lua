-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local cjson = require "cjson"
local config = require "config"
local fileUtils = require "file"
local user = require "user"
local ruleUtils = require "lib.ruleUtils"
local stringutf8 = require "stringutf8"

local tonumber = tonumber
local insert = table.insert

local _M = {}

local IP_GROUP_PATH = config.rulePath .. 'ipgroup.json'
local ACL_PATH = config.rulePath .. 'acl.json'

function _M.doRequest()
    local response = {code = 200, data = {}, msg = ""}
    local uri = ngx.var.uri
    local reload = false

    if user.checkAuthToken() == false then
        response.code = 401
        response.msg = 'User not logged in'
        ngx.status = 401
        ngx.say(cjson.encode(response))
        return ngx.exit(401)
    end

    if uri == "/common/ipgroups/list" then
        -- ip组列表
        response = ruleUtils.listRules(IP_GROUP_PATH)
    elseif uri == "/common/ipgroups/listnames" then
        local json = fileUtils.readFileToString(IP_GROUP_PATH)
        if json then
            local ruleTable = cjson.decode(json)
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
                response = ruleUtils.getRule(IP_GROUP_PATH, id)
            end
        else
            response.code = 500
            response.msg = err
            ngx.log(ngx.ERR, err)
        end
    elseif uri == "/common/ipgroups/update" then
        -- 修改ip组内容
        local newRule = ruleUtils.getRuleFromRequest()

        if newRule then
            newRule.id = tonumber(newRule.id)
            local ips = newRule.ips

            if not ips or #ips == 0 then
                response.code = 500
                response.msg = 'param content is empty'
            end

            response = ruleUtils.saveOrUpdateRule(IP_GROUP_PATH, newRule)
            reload = true
        else
            response.code = 500
            response.msg = 'param is empty'
        end
    elseif uri == "/common/ipgroups/remove" then
        -- 删除IP组
        local flag = false

        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()

        if args then
            local id = tonumber(args['id'])
            if id then
                local json = fileUtils.readFileToString(ACL_PATH)
                if json then
                    local ruleTable = cjson.decode(json)
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
                    response = ruleUtils.deleteRule(IP_GROUP_PATH)
                    reload = true
                end
            end
        else
            response.code = 500
            response.msg = err
        end
    end

    ngx.say(cjson.encode(response))

    -- 如果没有错误且需要重载配置文件则重载配置文件
    if (response.code == 200 or response.code == 0) and reload == true then
        config.reloadConfigFile()
    end
end

_M.doRequest()

return _M
