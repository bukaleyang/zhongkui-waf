-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local bit = require "bit"
local nkeys = require "table.nkeys"
local isempty = require "table.isempty"

local rshift = bit.rshift

local _M = {}

local INDEX_OUT_OF_RANGE = "String index out of range: "

function _M.binary_search(array, from_index, ro_index, item)
    if isempty(array) then
        return -1
    end

    if from_index > ro_index then
        error("out of range: " .. from_index .. "," .. ro_index)
    end

    if from_index < 1 then
        error(INDEX_OUT_OF_RANGE .. from_index)
    end

    local array_length = nkeys(array)
    if ro_index > array_length then
        error(INDEX_OUT_OF_RANGE .. ro_index)
    end

    local low = from_index
    local high = ro_index

    while low <= high do
        local mid = rshift(low + high, 1)
        --local mid = math.ceil((low + high) / 2)

        local midval = array[mid]
        if midval < item then
            low = mid + 1
        elseif midval > item then
            high = mid - 1
        else
            return mid
        end
    end

    return -low
end

return _M