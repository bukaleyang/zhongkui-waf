-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local cjson = require "cjson"
local lfs = require "lfs"
local ffi = require "ffi"

local lower = string.lower
local insert = table.insert
local pairs = pairs
local pcall = pcall
local cjson_decode = cjson.decode
local io_open = io.open
local IS_WINDOWS = ffi.os == "Windows"

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


local function log_error(...)
    if ngx and ngx.log and ngx.ERR then
        ngx.log(ngx.ERR, ...)
    end
end

local move_file_ex
local function init_move_file()
    if move_file_ex ~= nil then
        return move_file_ex
    end

    move_file_ex = false
    if not IS_WINDOWS then
        return false
    end

    local ok, kernel32 = pcall(ffi.load, "kernel32")
    if not ok then
        return false
    end

    pcall(ffi.cdef, [[
        int MoveFileExW(const uint16_t *lpExistingFileName, const uint16_t *lpNewFileName, unsigned long dwFlags);
        int MultiByteToWideChar(unsigned int CodePage, unsigned long dwFlags, const char *lpMultiByteStr, int cbMultiByte, uint16_t *lpWideCharStr, int cchWideChar);
    ]])

    local initialized = pcall(function()
        local multi_byte_to_wide = kernel32.MultiByteToWideChar
        local move = kernel32.MoveFileExW
        if not multi_byte_to_wide or not move then
            error("kernel32 symbols not found")
        end

        move_file_ex = function(source, target)
            local source_len = #source
            local target_len = #target
            local source_buffer = ffi.new("uint16_t[?]", source_len + 1)
            local target_buffer = ffi.new("uint16_t[?]", target_len + 1)

            if multi_byte_to_wide(65001, 0, source, source_len, source_buffer, source_len) == 0 then
                return false
            end
            if multi_byte_to_wide(65001, 0, target, target_len, target_buffer, target_len) == 0 then
                return false
            end

            source_buffer[source_len] = 0
            target_buffer[target_len] = 0

            return move(source_buffer, target_buffer, 9) ~= 0
        end
    end)

    if not initialized then
        move_file_ex = false
    end

    return move_file_ex ~= false
end

local function replace_file(source, target)
    if IS_WINDOWS and init_move_file() then
        if move_file_ex(source, target) then
            return true
        end
    end

    local ok, err = os.rename(source, target)
    if ok then
        return true
    end

    if IS_WINDOWS then
        os.remove(target)
        ok, err = os.rename(source, target)
    end

    return ok, err
end

local function make_temp_path(file_path)
    local suffix = tostring(os.time()) .. "_" .. tostring(math.random(100000, 999999))
    if ngx and ngx.now then
        suffix = suffix .. "_" .. tostring(math.floor(ngx.now() * 1000000))
    end
    if ngx and ngx.worker and ngx.worker.pid then
        suffix = suffix .. "_" .. tostring(ngx.worker.pid())
    end
    return file_path .. ".tmp." .. suffix
end

function _M.write_string_to_file_atomic(file_path, str)
    if not file_path or str == nil then
        return nil, "invalid file path or content"
    end

    local temp_path = make_temp_path(file_path)
    local file, err = io_open(temp_path, "w")
    if not file then
        log_error("Failed to open temp file ", temp_path, ": ", tostring(err))
        return nil, err
    end

    local ok, write_err = file:write(str)
    if not ok then
        file:close()
        os.remove(temp_path)
        return nil, write_err
    end

    local flushed, flush_err = file:flush()
    file:close()
    if not flushed then
        os.remove(temp_path)
        return nil, flush_err
    end

    local replaced, replace_err = replace_file(temp_path, file_path)
    if not replaced then
        os.remove(temp_path)
        log_error("Failed to replace file ", file_path, ": ", tostring(replace_err))
        return nil, replace_err
    end

    return true
end

function _M.write_binary_to_file(file_path, content)
    if content == nil then
        return nil, "invalid content"
    end

    local file, err = io_open(file_path, "wb")
    if not file then
        ngx.log(ngx.ERR, "Failed to open file ", err)
        return nil, err
    end

    local ok, write_err = file:write(content)
    if not ok then
        file:close()
        return nil, write_err
    end

    file:flush()
    file:close()
    return true
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