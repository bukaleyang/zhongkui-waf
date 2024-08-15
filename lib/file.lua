-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local cjson = require "cjson"
local lfs = require "lfs"

local toLower = string.lower
local insert = table.insert
local pairs = pairs
local pcall = pcall

local _M = {}

function _M.readRule(filePath, fileName)
	local file, err = io.open(filePath .. fileName .. ".json", "r")
    if not file then
   --     ngx.log(ngx.ERR, "Failed to open file ", err)
        return
    end

    local moduleName = nil
    local modules = {}
    local rulesTable = {}
    local otherTable = {}
    local text = file:read('*a')

	file:close()

    if #text > 0 then
        local result = cjson.decode(text)

        if result then
            moduleName = result.moduleName
            for key, value in pairs(result) do
                if key == "rules" then
                    for _, r in pairs(value) do
                        if toLower(r.state) == 'on' then
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

    modules.moduleName = moduleName or ''
    modules.rules = rulesTable

	return modules, otherTable
end

function _M.readFileToTable(filePath)
	local file, err = io.open(filePath, "r")
    if not file then
        ngx.log(ngx.ERR, "Failed to open file ", err)
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

function _M.readFileToString(filePath, binary)
    if not filePath then
        ngx.log(ngx.ERR, "No file found ", filePath)
        return
    end

    local mode = "r"
    if binary == true then
        mode = "rb"
    end

    local file, err = io.open(filePath, mode)
    if not file then
--        ngx.log(ngx.ERR, "Failed to open file ", err)
        return
    end

    local content = ""
    repeat
        local chunk = file:read(8192) -- 读取 8KB 的块
        if chunk then
            content = content .. chunk
        else
            break
        end
    until not chunk

    file:close()
    return content
end

function _M.writeStringToFile(filePath, str, append)
    if str == nil then
        return
	end

    local mode = 'w'
    if append == true then
        mode = 'a'
    end
	local file, err = io.open(filePath, mode)
    if not file then
        ngx.log(ngx.ERR, "Failed to open file ", err)
        return
    end

    file:write(str)
    file:flush()
	file:close()
end

function _M.removeFile(filePath)
    if not filePath then
        ngx.log(ngx.ERR, "No file found ", filePath)
        return
    end

    local success, err = os.remove(filePath)
    if success then
        ngx.log(ngx.INFO, filePath .. " has been successfully removed.")
    else
        ngx.log(ngx.ERR, "failed to remove file " .. filePath .. " " .. err)
    end
end

function _M.mkdir(path)
    local res, err = lfs.mkdir(path)
    if not res then
        ngx.log(ngx.ERR, err)
    end
    return res, err
end

function _M.is_directory(path)
    local attr = lfs.attributes(path)
    return attr and attr.mode == "directory"
end

function _M.rmdir(path)
    if not _M.is_directory(path) then
        return false, "failed to remove directory " .. path .. " is not a directory"
    end

    for entry in lfs.dir(path) do
        if entry ~= "." and entry ~= ".." then
            local e = path .. '/' .. entry

            local mode = lfs.attributes(e, "mode")

            if mode == "directory" then
                _M.rmdir(e)
            else
                _M.removeFile(e)
            end
        end
    end

    local res, err = lfs.rmdir(path)
    if not res then
        ngx.log(ngx.ERR, "failed to remove directory " .. path, err)
    end

    return res, err
end

function _M.is_file_exists(filePath)
    if not filePath then
        return false
    end

    local res, attr = pcall(lfs.attributes, filePath)
    if res and attr then
        return true
    end

    return false
end

return _M