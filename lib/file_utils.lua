-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local cjson = require "cjson"
local lfs = require "lfs"

local lower = string.lower
local insert = table.insert
local pairs = pairs
local pcall = pcall
local cjson_decode = cjson.decode
local io_open = io.open

local _M = {}

function _M.read_rule(file_path, file_name)
	local file, err = io_open(file_path .. file_name .. ".json", "r")
    if not file then
   --     ngx.log(ngx.ERR, "Failed to open file ", err)
        return
    end

    local moduleName = nil
    local modules = {}
    local table_rules = {}
    local table_other = {}
    local text = file:read('*a')

	file:close()

    if #text > 0 then
        local result = cjson_decode(text)

        if result then
            moduleName = result.moduleName
            for key, value in pairs(result) do
                if key == "rules" then
                    for _, r in pairs(value) do
                        if lower(r.state) == 'on' then
                            r.hits = 0
                            r.totalHits = 0
                            insert(table_rules, r)
                        end
                    end
                else
                    table_other[key] = value
                end
            end
        end
    end

    modules.moduleName = moduleName or ''
    modules.rules = table_rules

	return modules, table_other
end

function _M.read_file_to_table(file_path)
	local file, err = io_open(file_path, "r")
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

function _M.read_file_to_string(file_path, binary)
    if not file_path then
        ngx.log(ngx.ERR, "No file found ", file_path)
        return
    end

    local mode = "r"
    if binary == true then
        mode = "rb"
    end

    local file, err = io_open(file_path, mode)
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

function _M.write_string_to_file(file_path, str, append)
    if str == nil then
        return
	end

    local mode = 'w'
    if append == true then
        mode = 'a'
    end
	local file, err = io_open(file_path, mode)
    if not file then
        ngx.log(ngx.ERR, "Failed to open file ", err)
        return
    end

    file:write(str)
    file:flush()
	file:close()
end

function _M.remove_file(file_path)
    if not file_path then
        ngx.log(ngx.ERR, "No file found ", file_path)
        return
    end

    local success, err = os.remove(file_path)
    if success then
        ngx.log(ngx.INFO, file_path .. " has been successfully removed.")
    else
        ngx.log(ngx.ERR, "failed to remove file " .. file_path .. " " .. err)
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
                _M.remove_file(e)
            end
        end
    end

    local res, err = lfs.rmdir(path)
    if not res then
        ngx.log(ngx.ERR, "failed to remove directory " .. path, err)
    end

    return res, err
end

function _M.is_file_exists(file_path)
    if not file_path then
        return false
    end

    local res, attr = pcall(lfs.attributes, file_path)
    if res and attr then
        return true
    end

    return false
end

return _M