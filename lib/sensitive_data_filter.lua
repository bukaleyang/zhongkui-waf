-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local config = require "config"
local ahocorasick = require "ahocorasick"
local stringutf8 = require "stringutf8"
local file = require "file_utils"
local nkeys = require "table.nkeys"
local cjson = require "cjson"

local ipairs = ipairs
local pairs = pairs
local tonumber = tonumber

local sort = table.sort
local concat = table.concat

local ngxmatch = ngx.re.match
local ngxgmatch = ngx.re.gmatch
local ngxgsub = ngx.re.gsub
local ngxfind = ngx.re.find

local sub = string.sub
local gsub = string.gsub
local find = string.find
local rep = string.rep
local lower = string.lower
local utf8len = stringutf8.len
local utf8trim = stringutf8.trim
local to_char_array = stringutf8.to_char_array

local read_file_to_table = file.read_file_to_table
local read_file_to_string = file.read_file_to_string

local get_site_security_modules = config.get_site_security_modules
local is_global_option_on = config.is_global_option_on
local is_site_option_on = config.is_site_option_on

local cjson_decode = cjson.decode

local _M = {}

local STR_PREPROCESSING_REGEX = "[.,!?;:\"'()<>\\[\\]{}\\-_/\\|@#\\$%&\\*\\+=\\s]*"
local CODING_RANGE_REGEX = "(-*\\d+),(-*\\d+)"
local CODING_RANGE_DOLLAR_REGEX = "\\$(\\d+)"

local acs = {}

local function init_ac(file_path)
    local words = read_file_to_table(file_path) or {}
    if words and nkeys(words) > 0 then
        local ac = ahocorasick:new()
        ac:add(words)
        return ac
    end
end

local function load_site_sensitive_words_ac()
    local website_path = config.CONF_PATH .. '/website.json'
    local json = read_file_to_string(website_path)
    if json then
        local ac_global = nil
        if is_global_option_on('sensitiveDataFilter') then
            ac_global = init_ac(config.CONF_PATH .. '/global_rules/sensitiveWords')
            acs['global'] = ac_global
        end

        local t = cjson_decode(json)
        local sites = t.rules
        if sites then
            for _, site in pairs(sites) do
                local ac_site = nil

                local site_dir = config.CONF_PATH .. '/sites/' .. tostring(site.id)
                local config_file = site_dir .. '/config.json'
                local config_str = read_file_to_string(config_file)
                if config_str then
                    local site_config = cjson_decode(config_str)
                    if site_config and site_config.sensitiveDataFilter.state == 'on' then
                        ac_site = init_ac(site_dir .. '/rules/sensitiveWords')
                        if not ac_site then
                            ac_site = ac_global
                        end
                    end
                end

                if ac_site then
                    local server_names = site['serverNames']
                    for _, server in pairs(server_names) do
                        acs[server] = ac_site
                    end
                end
            end
        end
    end
end

load_site_sensitive_words_ac()

local function getRange(codingRange)
    local f, _ = find(codingRange, "$", 1, true)

    if f then
        local it, err = ngxgmatch(codingRange, CODING_RANGE_DOLLAR_REGEX, "isjo")
        if not it then
            ngx.log(ngx.ERR, "error: ", err)
            return
        end

        local t = {}

        while true do
            local m, error = it()
            if error then
                ngx.log(ngx.ERR, "error: ", error)
                return
            end

            if not m then
                break
            end

            table.insert(t, tonumber(m[1]))
        end

        return t
    else
        local m, err = ngxmatch(codingRange, CODING_RANGE_REGEX, "isjo")

        if m then
            local from, to = tonumber(m[1]), tonumber(m[2])
            if from then
                return from, to
            end
        else
            ngx.log(ngx.ERR, "error: ", err, codingRange)
            return
        end
    end

    return nil
end

local function codingString(strMatches, from, to)
    local str = strMatches[0]

    if from then
        if type(from) == 'table' then
            for _, v in ipairs(from) do
                local subStr = strMatches[v]
                local subStrLen = utf8len(subStr)
                local codedSubStr = rep("*", subStrLen)
                if codedSubStr then
                    str = gsub(str, subStr, codedSubStr)
                end
            end
        else
            local subStr = sub(str, from, to)
            local subStrLen = utf8len(subStr)
            local codedSubStr = rep("*", subStrLen)
            if codedSubStr then
                str = gsub(str, subStr, codedSubStr)
            end
        end
    else
        local strLen = utf8len(str)
        str = rep("*", strLen)
    end

    return str
end

function _M.textPreprocessing(text)
    if not text or text == '' then
        return text
    end

    text = utf8trim(text)
    text = lower(text)

    local temp, _, error = ngxgsub(text, STR_PREPROCESSING_REGEX, "", "jo")
    if temp then
        text = temp
    else
        ngx.log(ngx.ERR, "error: ", error)
    end

    return text
end

function _M.data_filter(content)
    if content == nil or content == '' then
        return
    end

    local rules = get_site_security_modules("sensitive").rules
    if rules then
        for _, rt in ipairs(rules) do
            local regex = rt.rule
            local codingRange = rt.codingRange

            local fr, _ = ngxfind(content, regex, "isjo")
            if fr then
                local it, err = ngxgmatch(content, regex, "isjo")
                if it then
                    local from, to = getRange(codingRange)
                    while true do
                        local m, error = it()
                        if error then
                            ngx.log(ngx.ERR, "error: ", error)
                            break
                        end

                        if not m then
                            break
                        end

                        local codedStr = codingString(m, from, to)
                        if codedStr then
                            content = gsub(content, m[0], codedStr)
                        end
                    end
                else
                    ngx.log(ngx.ERR, "error: ", err)
                end
            end
        end
    end

    if is_site_option_on('sensitiveDataFilter') then
        local server_name = ngx.ctx.server_name
        local ac_site = acs[server_name] or acs['global']
        if ac_site then
            local text = _M.textPreprocessing(content)
            local t = ac_site:match(text, true)
            if t and #t > 0 then
                sort(t)
                for _, value in ipairs(t) do
                    local array = to_char_array(value)
                    local regex = concat(array, STR_PREPROCESSING_REGEX)

                    content = ngxgsub(content, regex, codingString, "isj")
                end
            end
        end
    end

    return content
end

return _M
