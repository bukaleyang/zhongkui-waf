local cjson = require "cjson"
local file = require "file"
local pager = require "lib.pager"
local nkeys = require "table.nkeys"

local tonumber = tonumber
local insert = table.insert
local remove = table.remove

local _M = {}

-- 查询规则列表
function _M.listRules(filePath)
    local response = {code = 200, data = {}, msg = ""}

    if filePath then
        local json = file.readFileToString(filePath)
        if json then
            local ruleTable = cjson.decode(json)
            local rules = ruleTable.rules
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
            response.count = nkeys(ruleTable.rules)
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

-- 修改规则开关状态
function _M.updateRuleSwitchState(filePath)
    local response = {code = 200, data = {}, msg = ""}

    if filePath then
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()

        if args then
            local id = tonumber(args['id'])
            local state = args['state']
            local changed = false

            if id and state then
                local json = file.readFileToString(filePath)

                if json then
                    local ruleTable = cjson.decode(json)
                    local rules = ruleTable.rules

                    if rules then
                        for k, v in pairs(rules) do
                            if tonumber(v.id) == id and v.state ~= state then
                                rules[k].state = state
                                changed = true
                                break
                            end
                        end
                    end

                    if changed then
                        file.writeStringToFile(filePath, cjson.encode(ruleTable))
                    end
                end
            else
                local msg = 'param error'
                response.code = 500
                response.msg = msg
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

function _M.getRuleFromRequest()
    local newRule = nil
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
        local ruleStr = args['rule']
        if ruleStr then
            newRule = cjson.decode(ruleStr)
        end
    end

    return newRule
end

-- 修改规则
function _M.saveOrUpdateRule(filePath, newRule)
    local response = {code = 200, data = {}, msg = ""}

    if filePath and newRule and nkeys(newRule) > 0 then
        local json = file.readFileToString(filePath)
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

            file.writeStringToFile(filePath, cjson.encode(ruleTable))
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
                local json = file.readFileToString(filePath)

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

                    file.writeStringToFile(filePath, cjson.encode(ruleTable))
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

return _M