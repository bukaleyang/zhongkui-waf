-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local len = string.len
local sub = string.sub
local match = string.match
local byte = string.byte

local concat = table.concat
local insert = table.insert
local newtab = table.new
local abs = math.abs

local ngxfind = ngx.re.find

local error = error

local _M = {}

local INDEX_OUT_OF_RANGE = "String index out of range: "
local NOT_NUMBER = "number expected, got "
local NOT_STRING = "string expected, got "
local NOT_STRING_NIL = "string expected, got nil"

function _M.to_char_array(str)
    local array
    if str then
        local length = len(str)
        array = newtab(length, 0)

        local byteLength = 1
        local i, j = 1, 1
        while i <= length do
            local first_byte = byte(str, i)
            if first_byte >= 0 and first_byte < 128 then
                byteLength = 1
            elseif first_byte > 191 and first_byte < 224 then
                byteLength = 2
            elseif first_byte > 223 and first_byte < 240 then
                byteLength = 3
            elseif first_byte > 239 and first_byte < 248 then
                byteLength = 4
            end

            j = i + byteLength
            local char = sub(str, i, j - 1)
            i = j
            insert(array, char)
        end
    end

    return array
end

function _M.sub(str, i, j)
    local sub_str
    if str then
        if i == nil then
            i = 1
        end

        if type(i) ~= "number" then
            error(NOT_NUMBER .. type(i))
        end

        if i < 1 then
            error(INDEX_OUT_OF_RANGE .. i)
        end

        if j then
            if type(j) ~= "number" then
                error(NOT_NUMBER .. type(j))
            end
        end

        local array = _M.to_char_array(str)
        if array then
            local length = #array
            local subLen = length - i
            if subLen < 0 then
                error(INDEX_OUT_OF_RANGE .. subLen)
            end

            if not j then
                sub_str = concat(array, "", i)
            else
                if abs(j) > length then
                    error(INDEX_OUT_OF_RANGE .. j)
                end
                if j < 0 then
                    j = length + j + 1
                end
                sub_str = concat(array, "", i, j)
            end
        end
    end

    return sub_str
end

function _M.trim(str)
    if str then
        str = ngx.re.gsub(str, "^\\s*|\\s*$", "", "jo")
    end

    return str
end

function _M.len(str)
    local str_len = 0
    if str then
        if type(str) ~= "string" then
            error(NOT_STRING .. type(str))
        end

        local length = len(str)

        local i = 1
        while i <= length do
            local first_byte = byte(str, i)
            if first_byte >= 0 and first_byte < 128 then
                i = i + 1
            elseif first_byte > 191 and first_byte < 224 then
                i = i + 2
            elseif first_byte > 223 and first_byte < 240 then
                i = i + 3
            elseif first_byte > 239 and first_byte < 248 then
                i = i + 4
            end

            str_len = str_len + 1
        end
    else
        error(NOT_STRING_NIL)
    end

    return str_len
end

function _M.default_if_blank(str, default_str)
    if default_str == nil then
        default_str = ""
    end

    if str == nil or match(str, "^%s*$") then
        return default_str
    end

    return str
end

function _M.split(input_str, delimiter)
    if not input_str then
        return nil
    end

    local length = len(input_str)
    local result = {}

    if length == 0 then
        return result
    end

    local ctx = { pos = 1 }
    local start = 1

    while ctx.pos < length do
        local from = ngxfind(input_str, delimiter, "jo", ctx)

        if from then
            insert(result, sub(input_str, start, from - 1))
            start = ctx.pos
        else
            insert(result, sub(input_str, start, length))
            break
        end
    end

    return result
end

return _M
