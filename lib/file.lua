local cjson = require "cjson"

local toLower = string.lower
local insert = table.insert
local pairs = pairs

local _M = {}

function _M.readRule(filePath, fileName)
	local file = io.open(filePath .. fileName .. ".json", "r")
	if file == nil then
        return
	end

    local rulesTable = {}
    local otherTable = {}
    local text = file:read('*a')

	file:close()

    if #text > 0 then
        local result = cjson.decode(text)

        if result then
            for key, value in pairs(result) do
                if key == "rules" then
                    for _, r in pairs(value) do
                        if toLower(r.state) == 'on' then
                            r.ruleType = fileName
                            r.hits = 0
                            r.totalHits = 0
                            insert(rulesTable, r)
                        end
                    end
                else
                    otherTable[key] = value
                end
            end
        end
    end

	return rulesTable, otherTable
end

function _M.readFileToTable(filePath)
	local file = io.open(filePath, "r")
	if file == nil then
        return
	end

    local t = {}

	for line in file:lines() do
        line = string.gsub(line, "[\r\n]", "")
        table.insert(t, line)
	end

	file:close()

	return t
end

function _M.readFileToString(filePath)
	local file = io.open(filePath, "r")
	if file == nil then
        return
	end

    local text = file:read('*a')

	file:close()

	return text
end

return _M