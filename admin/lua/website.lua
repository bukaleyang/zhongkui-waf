-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

local cjson = require "cjson"
local config = require "config"
local user = require "user"
local rule_utils = require "lib.rule_utils"
local site_config = require "lib.site_config"

local cjson_encode = cjson.encode

local _M = {}

local WEBSITES_PATH = config.CONF_PATH .. '/website.json'

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

    if uri == "/sites/list" then
        -- 查询站点列表
        response = rule_utils.list_rules(WEBSITES_PATH)
    elseif uri == "/sites/save" then
        -- 修改或新增站点
        local newRule = rule_utils.get_rule_from_request()
        newRule.mode = 'protection'

        response = rule_utils.save_or_update_rule(WEBSITES_PATH, newRule)
        reload = true
    elseif uri == "/sites/remove" then
        -- 删除站点
        response = rule_utils.delete_rule(WEBSITES_PATH)
        reload = true
    end

    ngx.say(cjson_encode(response))

    -- 如果没有错误且需要重载配置文件则重新生成站点配置并重载 nginx
    if response.code == 200 and reload == true then
        site_config.generate()
        config.reload_config_file()
    end
end

_M.do_request()

return _M
