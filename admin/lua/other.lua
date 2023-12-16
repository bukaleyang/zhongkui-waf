local cjson = require "cjson"
local config = require "config"
local file = require "file"
local user = require "user"
local ruleUtils = require "lib.ruleUtils"

local _M = {}

local SENSITIVE_PATH = config.rulePath .. 'sensitive.json'
local SENSITIVE_WORDS_PATH = config.rulePath .. 'sensitiveWords'

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

    if uri == "/other/sensitive/get" then
        -- 查询配置信息
        local data = {}
        local configTable = config.getConfigTable()

        if configTable then
            data["sensitive_data_filtering"] = configTable.sensitive_data_filtering
        end

        local sensitiveWords = file.readFileToString(SENSITIVE_WORDS_PATH) or ''

        data["senstiveWords"] = sensitiveWords
        response.data = data
    elseif uri == "/other/sensitive/list" then
        -- 查询敏感词过滤规则
        response = ruleUtils.listRules(SENSITIVE_PATH)
    elseif uri == "/other/sensitive/save" then
        -- 修改或新增敏感数据过滤规则
        local newRule = ruleUtils.getRuleFromRequest()
        newRule.action = 'coding'

        response = ruleUtils.saveOrUpdateRule(SENSITIVE_PATH, newRule)
        reload = true
    elseif uri == "/other/sensitive/state" then
        -- 修改敏感词过滤规则开关状态
        response = ruleUtils.updateRuleSwitchState(SENSITIVE_PATH)
        reload = true
    elseif uri == "/other/sensitive/words/get" then
        -- 获取敏感词内容
        local content = file.readFileToString(SENSITIVE_WORDS_PATH) or ''

        response.data = {content = content}
    elseif uri == "/other/sensitive/words/update" then
        -- 修改敏感词
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
            content = args['content']
            if content then
                file.writeStringToFile(SENSITIVE_WORDS_PATH, content)
                reload = true
            end
        end
    end

    ngx.say(cjson.encode(response))

    -- 如果没有错误且需要重载配置文件则重载配置文件
    if response.code == 200 and reload == true then
        config.reloadConfigFile()
    end
end

_M.doRequest()

return _M
