local len = string.len
local sub = string.sub

local concat = table.concat
local insert = table.insert
local newtab = table.new
local abs = math.abs

local error = error

local _M = {}

local INDEX_OUT_OF_RANGE = "String index out of range: "
local NOT_NUMBER = "number expected, got "
local NOT_STRING = "string expected, got "
local NOT_STRING_NIL = "string expected, got nil"

function _M.toCharArray(str)
    local array
    if str then
        local length = len(str)
        array = newtab(length, 0)

        local byteLength = 1
        local i, j = 1, 1
        while i <= length do
            local firstByte = string.byte(str, i)
            if firstByte >=0 and firstByte < 128 then
                byteLength = 1
            elseif firstByte >191 and firstByte < 224 then
                byteLength = 2
            elseif firstByte >223 and firstByte < 240 then
                byteLength = 3
            elseif firstByte >239 and firstByte < 248 then
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
    local subStr
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

        local array = _M.toCharArray(str)
        if array then
            local length = #array
            local subLen = length - i
            if subLen < 0 then
                error(INDEX_OUT_OF_RANGE .. subLen)
            end

            if not j then
                subStr = concat(array, "", i)
            else
                if abs(j) > length then
                    error(INDEX_OUT_OF_RANGE .. j)
                end
                if j < 0 then
                    j = length + j + 1
                end
                subStr = concat(array, "", i, j)
            end
        end
    end

    return subStr
end

function _M.trim(str)
    if str then
        str = ngx.re.gsub(str, "^\\s*|\\s*$", "", "jo")
    end

    return str
end

function _M.len(str)
    local strLength = 0
    if str then
        if type(str) ~= "string" then
            error(NOT_STRING .. type(str))
        end

        local length = len(str)

        local i = 1
        while i <= length do
            local firstByte = string.byte(str, i)
            if firstByte >=0 and firstByte < 128 then
                i = i + 1
            elseif firstByte >191 and firstByte < 224 then
                i = i + 2
            elseif firstByte >223 and firstByte < 240 then
                i = i + 3
            elseif firstByte >239 and firstByte < 248 then
                i = i + 4
            end

            strLength = strLength + 1
        end
    else
        error(NOT_STRING_NIL)
    end

    return strLength
end

return _M