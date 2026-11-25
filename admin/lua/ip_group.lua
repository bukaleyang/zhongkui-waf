-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local cjson = require "cjson"
local config = require "config"
local file_utils = require "file_utils"
local user = require "user"
local rule_utils = require "lib.rule_utils"
local threat_intel = require "lib.threat_intel"

local tonumber = tonumber
local insert = table.insert

local cjson_decode = cjson.decode
local cjson_encode = cjson.encode

local _M = {}

local IP_GROUP_PATH = config.CONF_PATH .. '/ipgroup.json'
local ACL_PATH = config.CONF_PATH .. '/global_rules/acl.json'

-- 产品内置的威胁情报组，元数据丢失时也必须保持只读
local BUILTIN_IDS = {[1] = true, [2] = true}

local function is_managed(group)
    if not group then
        return false
    end

    return group.sourceUrl ~= nil or group.builtin == true or BUILTIN_IDS[tonumber(group.id)] == true
end

local function find_group(id)
    local json = file_utils.read_file_to_string(IP_GROUP_PATH)
    if not json then
        return nil
    end

    local rule_table = cjson_decode(json)
    for _, g in pairs(rule_table.rules or {}) do
        if tonumber(g.id) == tonumber(id) then
            return g
        end
    end
end

-- 元数据表明更新过，但本地数据文件已不存在（被删除或磁盘被清理）
local function data_file_missing(g)
    if not g.lastUpdate then
        return false
    end

    local rel = g.file
    if type(rel) ~= 'string' or rel == '' or rel:sub(1, 1) == '/'
        or rel:find('..', 1, true) or rel:find('\\', 1, true) then
        return true
    end

    return file_utils.is_file_exists(config.CONF_PATH .. '/' .. rel) ~= true
end

-- 列表不返回内置组的上万条 IP，只返回计数与更新状态
local function strip_managed_content(response)
    for _, g in pairs(response.data or {}) do
        if is_managed(g) then
            g.ips = nil
            g.ipCount = g.ipCount or 0
            g.fileMissing = data_file_missing(g)
            g.managed = true
        end
    end

    return response
end

function _M.do_request()
    local response = {code = 200, data = {}, msg = ""}
    local uri = ngx.var.uri
    local reload = false

    -- 本机调度器入口，由 admin.conf 限定只允许 127.0.0.1 访问
    if uri == "/common/ipgroups/refresh-due" then
        ngx.say(cjson_encode(threat_intel.refresh_due()))
        return
    end

    if user.check_auth_token() == false then
        response.code = 401
        response.msg = 'User not logged in'
        ngx.status = 401
        ngx.say(cjson_encode(response))
        return ngx.exit(401)
    end

    if uri == "/common/ipgroups/list" then
        -- ip组列表
        response = strip_managed_content(rule_utils.list_rules(IP_GROUP_PATH))
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
            if id and is_managed(find_group(id)) then
                response.code = 403
                response.msg = '该IP组由威胁情报自动维护，不支持直接编辑'
            elseif id then
                response = rule_utils.get_rule(IP_GROUP_PATH, id)
            end
        else
            response.code = 500
            response.msg = err
            ngx.log(ngx.ERR, err)
        end
    elseif uri == "/common/ipgroups/refresh" then
        -- 立即更新威胁情报组，id 为空时更新全部；force=1 跳过缩水保护
        if ngx.req.get_method() ~= "POST" then
            response.code = 405
            response.msg = 'Method Not Allowed'
        else
            ngx.req.read_body()
            local args = ngx.req.get_post_args() or {}
            if type(args) ~= 'table' then
                args = {}
            end

            if args.id ~= nil and (type(args.id) ~= 'string' or not tonumber(args.id)) then
                response.code = 400
                response.msg = '参数错误'
            else
                response = threat_intel.refresh({
                    id = args.id and tonumber(args.id) or nil,
                    force = args.force == '1',
                })
            end
        end
    elseif uri == "/common/ipgroups/update" then
        -- 修改ip组内容
        local newRule = rule_utils.get_rule_from_request()
        if newRule then
            newRule.id = tonumber(newRule.id)
            local ips = newRule.ips

            if is_managed(find_group(newRule.id)) then
                response.code = 403
                response.msg = '该IP组由威胁情报自动维护，不支持直接编辑'
            elseif not ips or #ips == 0 then
                response.code = 500
                response.msg = 'param content is empty'
            else
                response = rule_utils.save_or_update_rule(IP_GROUP_PATH, newRule)
                reload = true
            end
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

                if is_managed(find_group(id)) then
                    response.code = 403
                    response.msg = '该IP组由威胁情报自动维护，不能删除'
                elseif flag then
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
