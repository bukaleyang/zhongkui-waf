-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local config = require "config"
local redis_cli = require "redis_cli"
local constants = require "constants"
local request = require "request"
local cjson = require "cjson"

local concat = table.concat
local sort = table.sort
local type = type

local len = string.len
local sub = string.sub
local find = string.find
local md5 = ngx.md5
local ngxsub = ngx.re.sub
local ngxgsub = ngx.re.gsub
local pairs = pairs
local tonumber = tonumber
local tostring = tostring
local upper = string.upper
local cjson_decode = cjson.decode
local cjson_encode = cjson.encode

local get_site_config = config.get_site_config
local is_system_option_on = config.is_system_option_on
local is_site_option_on = config.is_site_option_on
local get_system_config = config.get_system_config
local get_site_security_modules = config.get_site_security_modules

local CHALLENGE_HTML = get_system_config().challenge_html
local SECRET = get_system_config("secret")

local _M = {}

math.randomseed(os.time())

-- 验证请求中的AccessToken，验证通过则返回true,否则返回false
function _M.check_access_token()
    local access_token = ngx.var.cookie_waf_accesstoken

    if not access_token then
        return false
    end

    local ctx = ngx.ctx
    local ip = ctx.ip
    local ua = ctx.ua
    local host = ctx.server_name
    local key = md5(ip .. ua .. host .. SECRET)

    local token = nil
    if is_system_option_on("redis") then
        token = redis_cli.get(constants.KEY_CAPTCHA_ACCESSTOKEN_REDIS_PREFIX .. key)
    else
        local limit = ngx.shared.dict_accesstoken
        token = limit:get(key)
    end

    if token and token == access_token then
        return true
    end

    return false
end

-- 设置浏览器cookie:access_token
function _M.set_access_token()
    local ctx = ngx.ctx
    local ip = ctx.ip
    local ua = ctx.ua
    local host = ctx.server_name
    local key = md5(ip .. ua .. host .. SECRET)
    local time = ngx.time()

    local expireInSeconds = get_site_config("bot").captcha.expireInSeconds

    local access_token = upper(md5(key .. time))
    local cookie_expire = ngx.cookie_time(time + expireInSeconds)
    ngx.header['Set-Cookie'] = { 'waf_accesstoken=' .. access_token .. '; path=/; Expires=' .. cookie_expire }

    if is_system_option_on("redis") then
        redis_cli.set(constants.KEY_CAPTCHA_ACCESSTOKEN_REDIS_PREFIX .. key, access_token, expireInSeconds)
    else
        local limit = ngx.shared.dict_accesstoken
        limit:set(key, access_token, expireInSeconds)
    end
end

-- 清除浏览器cookie:access_token
function _M.clear_access_token()
    ngx.header['Set-Cookie'] = { 'waf_accesstoken=; path=/; Expires=Thu, 01-Jan-1970 00:00:00 GMT' }
end

-- 获取请求签名
function _M.get_sign(args, sign_key, secret)
    local str = ''

    if args then
        sort(args)

        for key, val in pairs(args) do
            if key ~= sign_key then
                if type(val) == "table" then
                    str = str .. '&' .. key .. '=' .. concat(val, ", ")
                else
                    str = str .. '&' .. key .. '=' .. tostring(val)
                end
            end
        end

        local length = len(str)
        if length > 1 then
            str = sub(str, 2)
        end
    end

    str = str .. '&secret=' .. secret

    local sign = upper(md5(str))

    return sign
end

-- 验证请求签名
function _M.sign_verify(args, sign_key, secret)
    if args then
        local req_sign = args[sign_key]
        if not req_sign then
            return false
        end

        local sign = _M.get_sign(args, sign_key, secret)

        if req_sign == sign then
            return true
        end
    end

    return false
end

-- block ip
local function block_ip(ip, rule_table)
    if upper(rule_table.autoIpBlock) == "ON" and ip then
        local ok, err = nil, nil

        if is_system_option_on("redis") then
            local key = constants.KEY_BLACKIP_PREFIX .. ip

            ok, err = redis_cli.set(key, 1, rule_table.ipBlockExpireInSeconds)
            if ok then
                ngx.ctx.ip_blocked = true
            else
                ngx.log(ngx.ERR, "failed to block ip " .. ip, err)
            end
        else
            local blackip = ngx.shared.dict_blackip
            ok, err = blackip:set(ip, 1, rule_table.ipBlockExpireInSeconds)
            if ok then
                ngx.ctx.ip_blocked = true
            else
                ngx.log(ngx.ERR, "failed to block ip " .. ip, err)
            end
        end

        return ok
    end
end

local function get_random_formula()
    local operators = {'+', '-', '*', '/', 'pow', 'sqrt'}
    local length = #operators
    local index = 1

    local num = math.random(50)
    local result = num
    local formula = tostring(num)

    for i = 1, 3, 1 do
        num = math.random(50)
        index = math.random(length)
        local o = operators[index]
        if o == '+' then
            result = result + num
            formula = formula .. o .. tostring(num)
        elseif o == '-' then
            result = result - num
            formula = formula .. o .. tostring(num)
        elseif o == '*' then
            result = result * num
            formula = formula .. o .. tostring(num)
        elseif o == '/' then
            result = result / num
            formula = formula .. o .. tostring(num)
        elseif o == 'pow' then
            if result > 1 then
                num = math.random(5)
                result = math.pow(result, num)
                formula = 'Math.pow(' .. formula .. ',' .. tostring(num) .. ')'
            end
        elseif o == 'sqrt' then
            result = math.sqrt(math.abs(result))
            formula = 'Math.sqrt(Math.abs(' .. formula .. '))'
        end

        formula = '(' .. formula .. ')'
    end

    return formula, sub(tostring(result), 1, 10)
end

local function js_challenge()
    local args = {}
    local time = ngx.time()

    local req_sign = ngx.var.http_captcha_sign
    local req_time = tonumber(ngx.var.http_captcha_time)

    local captcha = get_site_config("bot").captcha

    local ctx = ngx.ctx
    local ip = ctx.ip
    local ua = ctx.ua
    local host = ctx.server_name
    local key_captcha = constants.KEY_CAPTCHA_PREFIX .. md5(ip .. ua .. host .. SECRET)
    local key_formula_result = key_captcha .. "_result"

    local uri = ngx.var.uri
    if uri == '/captcha/challenge' then
        local challenge_result = {result = 'fail'}

        if req_sign and req_time and ((req_time + captcha.verifyInSeconds) >= time) then
            args["Captcha-Sign"] = req_sign
            args["Captcha-Time"] = req_time
            local pass = _M.sign_verify(args, "Captcha-Sign", SECRET)
            if pass then
                args = request.get_post_args()
                if args then
                    local res = args['captcha_result']
                    if res then
                        local result = 0

                        if is_system_option_on("redis") then
                            result = redis_cli.get(key_formula_result)

                            if result then
                                local index = find(result, "_", 1 , true)
                                result = sub(result, index + 1)

                                if tonumber(res) == tonumber(result) then
                                    challenge_result = {result = 'success'}

                                    redis_cli.bath_del({key_captcha, key_formula_result})

                                    -- 设置访问令牌
                                    _M.set_access_token()
                                    ngx.ctx.is_captcha_pass = true
                                end
                            end
                        else
                            local limit = ngx.shared.dict_cclimit
                            result = limit:get(key_formula_result)

                            if result then
                                local index = find(result, "_", 1 , true)
                                result = sub(result, index + 1)

                                if tonumber(res) == tonumber(result) then
                                    challenge_result = {result = 'success'}

                                    limit:delete(key_formula_result)
                                    limit:delete(key_captcha)

                                    -- 设置访问令牌
                                    _M.set_access_token()
                                    ngx.ctx.is_captcha_pass = true
                                end
                            end
                        end
                    end
                end
            end
        end

        ngx.header.content_type = "application/json"
        local data_json = cjson_encode(challenge_result)
        ngx.print(data_json)

        return ngx.exit(ngx.HTTP_OK)
    end

    local formula, result = nil, nil

    -- 缓存公式计算结果
    if is_system_option_on("redis") then
        local content, _ = redis_cli.get(key_formula_result)
        if not content then
            formula, result = get_random_formula()
            redis_cli.set(key_formula_result, formula .. "_" .. result, captcha.verifyInSeconds)
        else
            local index = find(content, "_", 1 , true)
            formula = sub(content, 1, index - 1)
        end
    else
        local limit = ngx.shared.dict_cclimit
        local content, _ = limit:get(key_formula_result)
        if not content then
            formula, result = get_random_formula()
            limit:set(key_formula_result, formula .. "_" .. result, captcha.verifyInSeconds)
        else
            local index = find(content, "_", 1 , true)
            formula = sub(content, 1, index - 1)

            result = sub(content, index + 1)
        end
    end

    _M.clear_access_token()
    ngx.header.content_type = "text/html"

    --args["Captcha-Sign"] = req_sign
    args["Captcha-Time"] = time

    local sign = _M.get_sign(args, 'Captcha-Sign', SECRET)

    local headers = ngx.req.get_headers()

    -- 删除一些请求头
    headers.connection = nil
    headers.host = nil
    headers.cookie = nil
    headers["user-agent"] = nil
    headers["accept-encoding"] = nil

    local data = {
        method = ngx.req.get_method(),
        url = ngx.var.request_uri,
        body = request.get_request_body(),
        ["Captcha-Sign"] = sign,
        ["Captcha-Time"] = time
    }

    local data_json = cjson_encode(data)
    local headers_json = cjson_encode(headers)

    local html = CHALLENGE_HTML
    html = ngxgsub(html, "\\$request_data", data_json, "jo")
    html = ngxgsub(html, "\\$request_headers", headers_json, "jo")
    html = ngxsub(html, "\\$formula", formula, "jo")

    ngx.print(html)

    return ngx.exit(ngx.HTTP_OK)
end

local function do_captcha(module_name, rule_table)
    ngx.ctx.module_name = module_name
    ngx.ctx.rule_table = rule_table
    ngx.ctx.is_attack = false
    ngx.ctx.is_captcha = true
    ngx.ctx.is_blocked = true

    local captcha_type = upper(rule_table.type)
    if captcha_type == 'JS_CHALLENGE' then
        js_challenge()
    end
end

function _M.trigger_captcha()
    if is_site_option_on("bot") == false then
        return
    end

    local captcha = get_site_config("bot").captcha
    if captcha.state ~= "on" then
        return
    end

    if _M.check_access_token() then
        return
    end

    local ctx = ngx.ctx
    local ip = ctx.ip
    local ua = ctx.ua
    local host = ctx.server_name
    local key = constants.KEY_CAPTCHA_PREFIX .. md5(ip .. ua .. host .. SECRET)

    local module = get_site_security_modules("captcha")
    local rule_table = module.rules[1]

    if is_system_option_on("redis") then
        local count, _ = redis_cli.incr(key, rule_table.verifyInSeconds)
        if not count then
            redis_cli.set(key, 1, rule_table.verifyInSeconds)
        elseif tonumber(count) > rule_table.maxFailTimes then
            block_ip(ip, rule_table)
        end
    else
        local limit = ngx.shared.dict_cclimit
        local count, _ = limit:incr(key, 1, 0, rule_table.verifyInSeconds)
        if not count then
            limit:set(key, 1, rule_table.verifyInSeconds)
        elseif count > rule_table.maxFailTimes then
            block_ip(ip, rule_table)
        end
    end

    do_captcha(module.moduleName, rule_table)
end

function _M.check_captcha()
    if is_site_option_on("bot") == false then
        return
    end

    local captcha = get_site_config("bot").captcha
    if captcha.state ~= "on" then
        return
    end

    if _M.check_access_token() then
        return
    end

    local ctx = ngx.ctx
    local ip = ctx.ip
    local ua = ctx.ua
    local host = ctx.server_name
    local key = constants.KEY_CAPTCHA_PREFIX .. md5(ip .. ua .. host .. SECRET)

    local module = get_site_security_modules("captcha")
    local rule_table = module.rules[1]

    if is_system_option_on("redis") then
        local count, _ = redis_cli.get(key)
        if not count then
            return
        end

        if tonumber(count) > rule_table.maxFailTimes then
            block_ip(ip, rule_table)
        else
            redis_cli.incr(key)
        end
    else
        local limit = ngx.shared.dict_cclimit
        local count, _ = limit:get(key)
        if not count then
            return
        end

        if count > rule_table.maxFailTimes then
            block_ip(ip, rule_table)
        else
            limit:incr(key, 1)
        end
    end

    do_captcha(module.moduleName, rule_table)
end

return _M
