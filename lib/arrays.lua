local bit = require "bit"
local nkeys = require "table.nkeys"
local isempty = require "table.isempty"

local rshift = bit.rshift

local _M = {}

local INDEX_OUT_OF_RANGE = "String index out of range: "

function _M.binarySearch(array, fromIndex, toIndex, item)
    if isempty(array) then
        return -1
    end

    if fromIndex > toIndex then
        error("out of range: " .. fromIndex .. "," .. toIndex)
    end

    if fromIndex < 1 then
        error(INDEX_OUT_OF_RANGE .. fromIndex)
    end

    local arrayLength = nkeys(array)
    if toIndex > arrayLength then
        error(INDEX_OUT_OF_RANGE .. toIndex)
    end

    local low = fromIndex
    local high = toIndex

    while low <= high do
        local mid = rshift(low + high, 1)
        --local mid = math.ceil((low + high) / 2)

        local midVal = array[mid]
        if midVal < item then
            low = mid + 1
        elseif midVal > item then
            high = mid - 1
        else
            return mid
        end
    end

    return -low
end

return _M