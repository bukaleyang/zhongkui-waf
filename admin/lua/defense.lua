-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local cjson = require "cjson"
local config = require "config"
local file = require "file"
local user = require "user"
local ruleUtils = require "lib.ruleUtils"
local nkeys = require "table.nkeys"
local stringutf8 = require "stringutf8"

local tonumber = tonumber
local trim = stringutf8.trim
local gsub = string.gsub

local _M = {}

local CC_PATH = config.rulePath .. 'cc.json'
local ACL_PATH = config.rulePath .. 'acl.json'
local IP_WHITELIST_PATH = config.rulePath .. 'ipWhiteList'
local IP_BLACKLIST_PATH = config.rulePath .. 'ipBlackList'
local UA_PATH = config.rulePath .. 'user-agent.json'

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

    if uri == "/defense/basic/get" then
        -- 查询配置信息
        local configTable = config.getConfigTable()

        if configTable then
            response.data = cjson.encode(configTable)
        end
    elseif uri == "/defense/basic/update" then
        -- 修改配置
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()

        if args then
            for key, val in pairs(args) do
                if key == 'config' then
                    local configTable = cjson.decode(val)
                    config.updateConfigFile(configTable)
                    reload = true
                end
            end
        else
            response.code = 500
            response.msg = err
        end
    elseif uri == "/defense/rule/cc/list" then
        -- 查询cc规则
        response = ruleUtils.listRules(CC_PATH)
    elseif uri == "/defense/rule/cc/save" then
        -- 修改或新增cc规则
        local newRule = ruleUtils.getRuleFromRequest()

        if newRule then
            newRule.id = tonumber(newRule.id)
            newRule.duration = tonumber(newRule.duration)
            newRule.threshold = tonumber(newRule.threshold)
            newRule.ipBlockTimeout = tonumber(newRule.ipBlockTimeout)
            newRule.autoIpBlock = newRule.autoIpBlock or 'off'

            response = ruleUtils.saveOrUpdateRule(CC_PATH, newRule)
            reload = true
        else
            response.code = 500
            response.msg = 'param is empty'
        end
    elseif uri == "/defense/rule/cc/remove" then
        -- 删除cc规则
        response = ruleUtils.deleteRule(CC_PATH)
        reload = true
    elseif uri == "/defense/rule/cc/state" then
        -- 修改cc规则状态
        response = ruleUtils.updateRuleSwitchState(CC_PATH)
        reload = true
    elseif uri == "/defense/ipRule" then
        -- 查询配置信息
        local data = {}
        local configTable = config.getConfigTable()

        if configTable then
            data["whiteIP"] = configTable.whiteIP
            data["blackIP"] = configTable.blackIP
            data["geoip_disallow_country"] = configTable.geoip_disallow_country
        end

        response.data = data
    elseif uri == "/defense/ipRule/list" then
        -- ip黑白名单列表
        local data = {}
        local content = ''

        local ipWhiteList = file.readFileToTable(IP_WHITELIST_PATH)
        if ipWhiteList then
            local len = nkeys(ipWhiteList)
            if len > 1 then
                content = ipWhiteList[1] .. '...'
            elseif len > 0 then
                content = ipWhiteList[1]
            end
        end

        data[1] = {id = 1, state = config.get("whiteIP"), content = content}

        content = ''
        local ipBlackList = file.readFileToTable(IP_BLACKLIST_PATH)
        if ipBlackList then
            local len = nkeys(ipBlackList)
            if len > 1 then
                content = ipBlackList[1] .. '...'
            elseif len > 0 then
                content = ipBlackList[1]
            end
        end

        data[2] = {id = 2, state = config.get("blackIP"), content = content}

        response.data = data
        response.count = 2
        response.code = 0
    elseif uri == "/defense/ipRule/get" then
        -- ip黑白名单内容
        local args, err = ngx.req.get_uri_args()
        if args then
            local id = tonumber(args['id'])
            if id then
                local content = ''
                if id == 1 then
                    content = file.readFileToString(IP_WHITELIST_PATH) or ''
                elseif id == 2 then
                    content = file.readFileToString(IP_BLACKLIST_PATH) or ''
                end
                response.data = {id = id, content = content}
            end
        else
            response.code = 500
            response.msg = err
            ngx.log(ngx.ERR, err)
        end
    elseif uri == "/defense/ipRule/state" then
        -- 修改IP黑白名单启用状态
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()

        if args then
            local whiteIP = args['whiteIP']
            local blackIP = args['blackIP']
            local state = args['state']
            local configTable = {}

            if whiteIP and state then
                configTable.whiteIP = state
                config.updateConfigFile(configTable)
            elseif blackIP and state then
                configTable.blackIP = state
                config.updateConfigFile(configTable)
            else
                response.code = 500
                response.msg = 'ip rule data is empty'
            end
            reload = true
        else
            response.code = 500
            response.msg = err
            ngx.log(ngx.ERR, err)
        end
    elseif uri == "/defense/ipRule/update" then
        -- 修改ip黑白名单内容
        local id = nil
        local content = nil
        local args = nil

        ngx.req.read_body()

        local body_raw = ngx.req.get_body_data()
        if not body_raw then
            local body_file = ngx.req.get_body_file()
            if body_file then
                body_raw = file.readFileToString(body_file)
            end
        end

        if body_raw and body_raw ~= "" then
            args = ngx.decode_args(body_raw, 0)
        end

        if args then
            id = tonumber(args['id'])
            content = args['content']

            if id and content then
                if id == 1 then
                    file.writeStringToFile(IP_WHITELIST_PATH, content)
                elseif id == 2 then
                    file.writeStringToFile(IP_BLACKLIST_PATH, content)
                end
                reload = true
            end
        end
    elseif uri == "/defense/ipRule/geoip/update" then
        -- 修改地域级IP黑名单配置
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()

        if args then
            local val = args['geoip_disallow_country']
            if val then
                local configTable = {geoip_disallow_country = cjson.decode(val)}
                config.updateConfigFile(configTable)
                reload = true
            end
        else
            response.code = 500
            response.msg = err
        end
    elseif uri == "/defense/rule/acl/list" then
        -- 查询acl规则
        response = ruleUtils.listRules(ACL_PATH)
    elseif uri == "/defense/rule/acl/save" then
        -- 修改或新增acl规则
        local newRule = ruleUtils.getRuleFromRequest()

        if newRule then
            newRule.id = tonumber(newRule.id)
            newRule.ipBlockTimeout = tonumber(newRule.ipBlockTimeout)
            newRule.autoIpBlock = newRule.autoIpBlock or 'off'

            -- 将匹配逻辑操作符转换为对应正则表达式
            local conditions = newRule.conditions
            if conditions then
                for _, c in pairs(conditions) do
                    local operator = c.operator
                    local content = trim(c.content)
                    local pattern = ''
                    if operator == 'prefix' then
                        pattern = '^' .. content
                    elseif operator == 'suffix' then
                        pattern = content .. '$'
                    elseif operator == 'contains' then
                        pattern = content
                    elseif operator == 'not' then
                        pattern = '^(?:(?!' .. content .. ').)*$'
                    elseif operator == 'notexist' then
                        pattern = ''
                    elseif operator == 'equal' then
                        pattern = '^' .. content .. '$'
                    elseif operator == 'regex' then
                        pattern = content
                    end
                    c.pattern = pattern
                end
            end
            response = ruleUtils.saveOrUpdateRule(ACL_PATH, newRule)
            reload = true
        else
            response.code = 500
            response.msg = 'param is empty'
        end
    elseif uri == "/defense/rule/acl/remove" then
        -- 修改或新增cc规则
        response = ruleUtils.deleteRule(ACL_PATH)
        reload = true
    elseif uri == "/defense/rule/acl/state" then
        -- 修改cc规则开关状态
        response = ruleUtils.updateRuleSwitchState(ACL_PATH)
        reload = true
    elseif uri == "/defense/rule/ua/list" then
        -- 查询ua规则
        response = ruleUtils.listRules(UA_PATH)
    elseif uri == "/defense/rule/ua/save" then
        -- 修改或新增ua规则
        local newRule = ruleUtils.getRuleFromRequest()

        if newRule then
            newRule.id = tonumber(newRule.id)
            newRule.ipBlockTimeout = tonumber(newRule.ipBlockTimeout)
            newRule.autoIpBlock = newRule.autoIpBlock or 'off'

            local rule = newRule.rule
            if rule then
                rule = gsub(rule, '\n', '|')
            end
            newRule.rule = rule
            response = ruleUtils.saveOrUpdateRule(UA_PATH, newRule)
            reload = true
        else
            response.code = 500
            response.msg = 'param is empty'
        end
    elseif uri == "/defense/rule/ua/state" then
        -- 修改ua规则状态
        response = ruleUtils.updateRuleSwitchState(UA_PATH)
        reload = true
    end

    ngx.say(cjson.encode(response))

    -- 如果没有错误且需要重载配置文件则重载配置文件
    if (response.code == 200 or response.code == 0) and reload == true then
        config.reloadConfigFile()
    end
end

_M.doRequest()

return _M
