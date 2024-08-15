-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local cjson = require "cjson"
local config = require "config"
local file = require "file"
local pager = require "lib.pager"
local nkeys = require "table.nkeys"

local tonumber = tonumber
local pairs = pairs
local insert = table.insert
local remove = table.remove
local cjson_decode = cjson.decode
local cjson_encode = cjson.encode

local update_site_module_rule_file = config.update_site_module_rule_file
local get_site_module_rule_file = config.get_site_module_rule_file
local readFileToString = file.readFileToString
local writeStringToFile = file.writeStringToFile

local _M = {}

-- 查询规则列表
function _M.listRules(filePath, list_key)
    local response = {code = 200, data = {}, msg = ""}

    if filePath then
        local json = readFileToString(filePath)
        if json then
            local ruleTable = cjson_decode(json)
            local rules = ruleTable[list_key or 'rules']
            local data = {}

            local args, err = ngx.req.get_uri_args()
            if args then
                local page = tonumber(args['page'])
                local limit = tonumber(args['limit'])

                local begin = pager.getLuaBegin(page, limit)
                local endPage = pager.getLuaEnd(page, limit)
                local k = 1

                for i = begin, endPage do
                    data[k] = rules[i]
                    k = k + 1
                end
            else
                response.code = 500
                response.msg = err
            end

            response.code = 0
            response.count = nkeys(ruleTable[list_key or 'rules'])
            response.data = data
        end
    else
        response.code = 500
        response.msg = 'filePath error'
    end

    if response.code ~= 0 then
        ngx.log(ngx.ERR, response.msg)
    end

    return response
end

-- 根据id查询规则
function _M.getRule(filePath, id)
    local response = {code = 200, data = {}, msg = ""}

    if filePath then
        local json = readFileToString(filePath)
        if json then
            local ruleTable = cjson_decode(json)
            local rules = ruleTable.rules
            local rule = nil

            if not id then
                local args, err = ngx.req.get_uri_args()
                if not args or not args['id'] then
                    ngx.req.read_body()
                    args, err = ngx.req.get_post_args()
                end

                if args then
                    id = args['id']
                else
                    response.code = 500
                    response.msg = err
                end
            end

            if id then
                id = tonumber(id)
                for _, r in pairs(rules) do
                    if r.id == id then
                        rule = r
                        break
                    end
                end
            end

            response.data = rule
        end
    else
        response.code = 500
        response.msg = 'filePath error'
    end

    return response
end

function _M.getRuleFromRequest()
    local newRule = nil
    local args = nil
    ngx.req.read_body()

    local body_raw = ngx.req.get_body_data()
    if not body_raw then
        local body_file = ngx.req.get_body_file()
        if body_file then
            body_raw = readFileToString(body_file)
        end
    end

    if body_raw and body_raw ~= "" then
        args = ngx.decode_args(body_raw, 0)
    end

    if args then
        local ruleStr = args['rule']
        if ruleStr then
            newRule = cjson_decode(ruleStr)
        end
    end

    return newRule
end

-- 修改规则
function _M.saveOrUpdateRule(filePath, newRule)
    local response = {code = 200, data = {}, msg = ""}

    if filePath and newRule and nkeys(newRule) > 0 then
        local json = readFileToString(filePath)
        if json then
            local ruleTable = cjson.decode(json)
            local rules = ruleTable.rules

            newRule.id = tonumber(newRule.id)
            -- 有id则是修改，否则是新增
            if newRule.id then
                for k, v in pairs(rules) do
                    if tonumber(v.id) == newRule.id then
                        rules[k] = newRule
                        break
                    end
                end
            else
                local nextId = tonumber(ruleTable.nextId) or nkeys(rules) + 1
                newRule.id = nextId
                insert(rules, newRule)
                ruleTable.nextId = nextId + 1
            end

            writeStringToFile(filePath, cjson.encode(ruleTable))
        end
    else
        local msg = 'param error'
        response.code = 500
        response.msg = msg
    end

    if response.code ~= 200 then
        ngx.log(ngx.ERR, response.msg)
    end

    return response
end

-- 删除规则
function _M.deleteRule(filePath)
    local response = {code = 200, data = {}, msg = ""}

    if filePath then
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()

        if args then
            local id = tonumber(args['id'])
            if id then
                local json = readFileToString(filePath)

                if json then
                    local ruleTable = cjson.decode(json)
                    local rules = ruleTable.rules

                    if rules then
                        for k, v in pairs(rules) do
                            if tonumber(v.id) == id then
                                remove(rules, k)
                                break
                            end
                        end
                    end

                    writeStringToFile(filePath, cjson.encode(ruleTable))
                end
            else
                response.code = 500
                response.msg = 'param id is empty'
            end
        else
            response.code = 500
            response.msg = err
        end
    else
        response.code = 500
        response.msg = 'filePath error'
    end

    if response.code ~= 200 then
        ngx.log(ngx.ERR, response.msg)
    end

    return response
end


-- 修改站点规则开关状态
function _M.update_site_rule_state(site_id, module_id, rule_id, state)
    local response = {code = 200, data = {}, msg = ""}
    rule_id = tonumber(rule_id)

    if site_id and module_id and rule_id and state then
        local _, content = get_site_module_rule_file(site_id, module_id)
        if content then
            local t = cjson_decode(content)
            local rules = t.rules
            local changed = false

            for _, r in pairs(rules) do
                if r.id == rule_id and r.state ~= state then
                    r.state = state
                    changed = true
                    break
                end
            end

            if changed then
                local json = cjson_encode(t)
                update_site_module_rule_file(site_id, module_id, json)
            end
        end
    else
        response.code = 500
        response.msg = 'param error'
    end

    if response.code ~= 200 then
        ngx.log(ngx.ERR, response.msg)
    end

    return response
end

-- 保存或修改站点规则
function _M.save_or_update_site_rule(site_id, module_id, rule_new)
    local response = {code = 200, data = {}, msg = ""}

    if site_id and module_id and rule_new and nkeys(rule_new) > 0 then
        local _, json = get_site_module_rule_file(site_id, module_id)
        if json then
            local rule_table = cjson_decode(json)
            local rules = rule_table.rules

            rule_new.id = tonumber(rule_new.id)
            -- 有id则是修改，否则是新增
            if rule_new.id then
                for k, v in pairs(rules) do
                    if tonumber(v.id) == rule_new.id then
                        rules[k] = rule_new
                        break
                    end
                end
            else
                local nextId = tonumber(rule_table.nextId) or nkeys(rules) + 1
                rule_new.id = nextId
                insert(rules, rule_new)
                rule_table.nextId = nextId + 1
            end

            update_site_module_rule_file(site_id, module_id, cjson_encode(rule_table))
        end
    else
        local msg = 'param error'
        response.code = 500
        response.msg = msg
    end

    if response.code ~= 200 then
        ngx.log(ngx.ERR, response.msg)
    end

    return response
end

-- 删除站点规则
function _M.delete_site_rule(site_id, module_id, rule_id)
    local response = {code = 200, data = {}, msg = ""}
    rule_id = tonumber(rule_id)

    if site_id and module_id and rule_id then
        local _, content = get_site_module_rule_file(site_id, module_id)
        if content then
            local t = cjson_decode(content)
            local rules = t.rules
            local changed = false

            if rules then
                for k, r in pairs(rules) do
                    if r.id == rule_id then
                        remove(rules, k)
                        changed = true
                        break
                    end
                end
            end

            if changed then
                local json = cjson_encode(t)
                update_site_module_rule_file(site_id, module_id, json)
            end
        end
    else
        response.code = 500
        response.msg = 'param error'
    end

    if response.code ~= 200 then
        ngx.log(ngx.ERR, response.msg)
    end

    return response
end

return _M