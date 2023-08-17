local config = require "config"
local ahocorasick = require "ahocorasick"
local stringutf8 = require "stringutf8"
local nkeys = require "table.nkeys"

local ipairs = ipairs
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
local tonumber = tonumber
local utf8len = stringutf8.len
local utf8trim = stringutf8.trim
local toCharArray = stringutf8.toCharArray

local _M = {}

local STR_PREPROCESSING_REGEX = "[.,!?;:\"'()<>\\[\\]{}\\-_/\\|@#\\$%&\\*\\+=\\s]*"
local CODING_RANGE_REGEX = "(-*\\d+),(-*\\d+)"
local CODING_RANGE_DOLLAR_REGEX = "\\$(\\d+)"

local rules = config.rules.sensitive
local sensitiveWords = config.rules.sensitiveWords
local needFilterSensitiveWords = false
local ac = ahocorasick:new()

local function initSensitiveWordsAC()
    if sensitiveWords then
        local wordsList = sensitiveWords["words"]
        if wordsList and nkeys(wordsList) > 0 then
            ac:add(wordsList)
            needFilterSensitiveWords = true
        end
    end
end

initSensitiveWordsAC()

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

function _M.sensitive_data_filtering(content)
    if content == nil or content == '' then
        return
    end

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

    if needFilterSensitiveWords then
        local text = _M.textPreprocessing(content)
        local t = ac:match(text, true)
        if t and #t > 0 then
            sort(t)
            for _, value in ipairs(t) do
                local array = toCharArray(value)
                local regex = concat(array, STR_PREPROCESSING_REGEX)

                content = ngxgsub(content, regex, codingString, "isj")
            end
        end
    end

    return content
end

return _M
