-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local tonumber = tonumber

local _M = {}

local mt = { __index = _M }

function _M:new(page, limit)
    page = tonumber(page) or 1 -- 第几页
    if page < 1 then
        page = 1
    end

    local t = {
        page = tonumber(page) or 1, -- 第几页
        limit = tonumber(limit) or 10, -- 每页大小
        totalPages = 0, -- 总页数
        totalSize = 0 -- 总记录数
    }

    setmetatable(t, mt)
    return t
end

local function get_page(page)
    page = tonumber(page) or 1
    if page < 1 then
        page = 1
    end
    return page
end

local function get_limit(limit)
    limit = tonumber(limit) or 10
    if limit < 1 then
        limit = 1
    end
    return limit
end

-- 获取起始下标，从0开始
function _M.get_begin(page, limit)
    page = get_page(page)
    limit = get_limit(limit)
    return (page - 1) * limit
end

-- 获取截止下标，从0开始
function _M.get_end(page, limit)
    page = get_page(page)
    limit = get_limit(limit)
    return (page - 1) * limit + limit - 1
end

-- 获取起始下标，从1开始
function _M.get_lua_begin(page, limit)
    page = get_page(page)
    limit = get_limit(limit)
    return (page - 1) * limit + 1
end

-- 获取截止下标，从1开始
function _M.get_lua_end(page, limit)
    page = get_page(page)
    limit = get_limit(limit)
    return (page - 1) * limit + limit
end

return _M
