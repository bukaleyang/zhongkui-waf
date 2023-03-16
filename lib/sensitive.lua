local config = require "config"
local ahocorasick = require "ahocorasick"
local stringutf8 = require "stringutf8"

local ipairs = ipairs
local sort = table.sort

local ngxmatch = ngx.re.match
local ngxgmatch = ngx.re.gmatch
local ngxgsub = ngx.re.gsub
local ngxfind = ngx.re.find

local sub = string.sub
local gsub = string.gsub
local find = string.find
local rep = string.rep
local tonumber = tonumber
local utf8len = stringutf8.len

local _M = {}

local rules = config.rules.sensitive
local sensitiveWords = config.rules.sensitiveWords
local ac = ahocorasick:new()

local function initSensitiveWordsAC()
    if sensitiveWords then
        local wordsList = sensitiveWords["words"]
        if wordsList then
            ac:add(wordsList)
        end
    end
end

initSensitiveWordsAC()

local codingRangeRegex = "(-*\\d+),(-*\\d+)"

local function getRange(codingRange)
    local f, _ = find(codingRange, "$", 1, true)

    if f then
        local it, err = ngxgmatch(codingRange, "\\$(\\d+)", "isjo")
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
        local m, err = ngxmatch(codingRange, codingRangeRegex, "isjo")

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
        if type(from) =='table' then
            for _, v in ipairs(from) do
                local subStr = strMatches[v]
                --[[local codedSubStr, _, error = ngxgsub(subStr, ".", "*", "jo")
                if codedSubStr then
                    str = gsub(str, subStr, codedSubStr)
                else
                    ngx.log(ngx.ERR, "error: ", error)
                end]]
                local codedSubStr = rep("*", #subStr)
                if codedSubStr then
                    str = gsub(str, subStr, codedSubStr)
                end
            end
        else
            local subStr = sub(str, from, to)
            local codedSubStr = rep("*", #subStr)
            if codedSubStr then
                str = gsub(str, subStr, codedSubStr)
            end
        end
    end

    return str
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

    if sensitiveWords then
        local t = ac:match(content, true)
        if t and #t > 0 then
            sort(t)
            for _, value in ipairs(t) do
                local codedSubStr = rep("*", utf8len(value))
                if codedSubStr then
                    content = gsub(content, value, codedSubStr)
                end
            end
        end
    end

    return content
end

return _M