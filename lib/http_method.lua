-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2026 bukale bukale2022@163.com

-- HTTP 方法白名单：state=on 的规则表示允许，其余方法一律拦截。

local _M = {}

local upper = string.upper
local lower = string.lower
local gsub = string.gsub
local type = type
local match = string.match

local MAX_LEN = 32

-- 方法名去掉首尾空白并转大写；含空格等非法字符返回 nil
function _M.normalize(method)
    if type(method) ~= "string" then
        return nil
    end

    method = gsub(upper(method), "^%s+", "")
    method = gsub(method, "%s+$", "")
    if #method == 0 or #method > MAX_LEN or not match(method, "^[A-Z][A-Z0-9_-]*$") then
        return nil
    end

    return method
end

-- 与 file_utils.read_rule 保持一致：state 不区分大小写
function _M.is_enabled(rule)
    return type(rule) == "table" and lower(tostring(rule.state or "")) == "on"
end

-- 收集允许的方法集合，非法规则值忽略
function _M.build_allowed(rules)
    local allowed = {}

    for _, r in pairs(rules or {}) do
        if _M.is_enabled(r) then
            local method = _M.normalize(r.rule)
            if method then
                allowed[method] = true
            end
        end
    end

    return allowed
end

function _M.is_allowed(method, allowed)
    local name = _M.normalize(method)
    return name ~= nil and allowed[name] == true
end

return _M
