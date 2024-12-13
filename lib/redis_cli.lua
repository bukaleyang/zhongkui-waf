-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local redis = require "resty.redis"
local config = require "config"
-- register the module prefix "bf" for RedisBloom
-- redis.register_module_prefix("bf")

local tonumber = tonumber
local tostring = tostring
local ipairs = ipairs
local lower = string.lower
local ngxmatch = ngx.re.match
local get_system_config = config.get_system_config

local _M = {}

local redis_config = get_system_config("redis")
local host = redis_config.host
local port = redis_config.port
local password = redis_config.password
local poolSize = redis_config.poolSize
local ssl = lower(redis_config.ssl) == 'on' and true or false

local redis_timeouts = redis_config.timeouts
local connect_timeout, send_timeout, read_timeout = 1000, 1000, 1000
if redis_timeouts then
    local m, err = ngxmatch(tostring(redis_timeouts), "(\\d+),(\\d+),(\\d+)")
    if m then
        connect_timeout = tonumber(m[1]) or 1000
        send_timeout = tonumber(m[2]) or 1000
        read_timeout = tonumber(m[3]) or 1000
    else
        ngx.log(ngx.ERR, "failed to read redis timeouts config:", err)
    end
end

--local filterName = "blackIpFilter"

function _M.get_connection()
    local red, err1 = redis:new()
    if not red then
        ngx.log(ngx.ERR, "failed to new redis:", err1)
        return nil, err1
    end

    red:set_timeouts(connect_timeout, send_timeout, read_timeout)

    local ok, err = red:connect(host, port or 6379, { ssl = ssl, pool_size = poolSize })

    if not ok then
        ngx.log(ngx.ERR, "failed to connect: ", err .. "\n")
        return nil, err
    end

    if password ~= nil and #password ~= 0 then
        local times = 0
        times, err = red:get_reused_times()

        if times == 0 then
            local res, err2 = red:auth(password)
            if not res then
                ngx.log(ngx.ERR, "failed to authenticate: ", err2)
                return nil, err2
            end
        end
    end

    return red, err
end

function _M.close_connection(red)
    -- put it into the connection pool of size 100,
    -- with 10 seconds max idle time
    local ok, err = red:set_keepalive(10000, 100)
    if not ok then
        ngx.log(ngx.ERR, "failed to set keepalive: ", err)
    end

    return ok, err
end

function _M.set(key, value, expire_time)
    local red, _ = _M.get_connection()
    local ok, err = nil, nil
    if red then
        ok, err = red:set(key, value)
        if not ok then
            ngx.log(ngx.ERR, "failed to set key: " .. key .. " ", err)
        elseif expire_time and expire_time > 0 then
            red:expire(key, expire_time)
        end

        _M.close_connection(red)
    end

    return ok, err
end

function _M.bath_set(key_table, value, key_prefix)
    local red, _ = _M.get_connection()
    local results, err = nil, nil
    if red then
        red:init_pipeline()

        if key_prefix then
            for _, k in ipairs(key_table) do
                red:set(key_prefix .. k, value)
            end
        else
            for _, k in ipairs(key_table) do
                red:set(k, value)
            end
        end

        results, err = red:commit_pipeline()
        if not results then
            ngx.log(ngx.ERR, "failed to set keys: ", err)
        end

        _M.close_connection(red)
    end

    return results, err
end

function _M.get(key)
    local red, err = _M.get_connection()
    local value = nil
    if red then
        value, err = red:get(key)
        if not value then
            ngx.log(ngx.ERR, "failed to get key: " .. key, err)
            return value, err
        end
        if value == ngx.null then
            value = nil
        end

        _M.close_connection(red)
    end

    return value, err
end

function _M.incr(key, expire_time)
    local red, err = _M.get_connection()
    local res = nil
    if red then
        res, err = red:incr(key)
        if not res then
            ngx.log(ngx.ERR, "failed to incr key: " .. key, err)
        elseif res == 1 and expire_time and expire_time > 0 then
            red:expire(key, expire_time)
        end

        _M.close_connection(red)
    end

    return res, err
end

function _M.del(key)
    local red, err = _M.get_connection()
    local res = nil
    if red then
        res, err = red:del(key)
        if not res then
            ngx.log(ngx.ERR, "failed to delete key: " .. key, err)
        end

        _M.close_connection(red)
    end

    return res, err
end

function _M.bath_del(key_table, key_prefix)
    local red, _ = _M.get_connection()
    local results, err = nil, nil
    if red then
        red:init_pipeline()

        if key_prefix then
            for _, k in ipairs(key_table) do
                red:del(key_prefix .. k)
            end
        else
            for _, k in ipairs(key_table) do
                red:del(k)
            end
        end

        results, err = red:commit_pipeline()
        if not results then
            ngx.log(ngx.ERR, "failed to delete keys: ", err)
        end

        _M.close_connection(red)
    end

    return results, err
end

--[[
function _M.bf_add(value)
    local red, err = _M.get_connection()
    local res = nil
    if red then
        -- call BF.ADD command with the prefix 'bf'
        res, err = red:bf():add(filterName, value)
        if not res then
            ngx.log(ngx.ERR, "bf():add value: " .. value, err)
            return res, err
        end

        _M.close_connection(red)
    end
    return res, err
end

function _M.bf_exists(value)
    local red, err = _M.get_connection()
    local res = nil
    if red then
        -- call BF.EXISTS command
        res, err = red:bf():exists(filterName, value)
        if not res then
            ngx.log(ngx.ERR, "bf():exists value: " .. value, err)
            return res, err
        elseif res == 1 then
            _M.close_connection(red)
            return true
        else
            _M.close_connection(red)
            return false
        end
    end
    return false
end
]]
return _M
