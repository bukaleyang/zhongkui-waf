local redis = require "resty.redis"
local config = require "config"
-- register the module prefix "bf" for RedisBloom
redis.register_module_prefix("bf")

local _M = {}

local host = config.get("redis_host")
local port = 6379
local redis_port = config.get("redis_port")
if redis_port ~= nil and redis_port ~= "" then
    port = tonumber(redis_port)
end

local passwd = config.get("redis_passwd")

local poolSize = config.get("redis_pool_size")

local redis_timeouts = config.get("redis_timeouts")
local connect_timeout, send_timeout, read_timeout = 1000, 1000, 1000
if redis_timeouts then
    connect_timeout = tonumber(string.match(config.get("redis_timeouts"), "(%d+),%d+,%d+"))
    send_timeout = tonumber(string.match(config.get("redis_timeouts"), "%d+,(%d+),%d+"))
    read_timeout = tonumber(string.match(config.get("redis_timeouts"), "%d+,%d+,(%d+)"))
end

local redisSSL = config.get("redis_ssl")
local filterName = "blackIpFilter"
local logPath = config.get("logPath")

local function getRedisConn()

    local red = redis:new()

    red:set_timeouts(connect_timeout, send_timeout, read_timeout)

    local ok, err = red:connect(host, port, {ssl = redisSSL, pool_size = poolSize})

    if not ok then
        ngx.log(ngx.ERR, "failed to connect: " .. err .. "\n", err)
        return ok, err
    end

    if passwd ~= nil and pwsswd ~= ngx.null then
        local times = 0
        times, err = red:get_reused_times()

        if times == 0 then
            local res, err = red:auth(passwd)
            if not res then
                ngx.log(ngx.ERR, "failed to authenticate: " .. err .. "\n", err)
                return times, err
            end
        end
    end

    return red, err
end

local function closeRedisConn(red)
    -- put it into the connection pool of size 100,
    -- with 10 seconds max idle time
    local ok, err = red:set_keepalive(10000, 100)
    if not ok then
        ngx.log(ngx.ERR, "failed to set keepalive: " .. err .. "\n", err)
        return
    end
end

function _M.redisSet(key, value, expireTime)
    local red, err = getRedisConn()
    if red then
        local ok, err = red:set(key, value)
        if not ok then
            ngx.log(ngx.ERR, "failed to set key: " .. key .. " "  .. err .. "\n", err)
            return ok, err
        elseif expireTime and expireTime > 0 then
            red:expire(key, expireTime)
        end

        closeRedisConn(red)
    end
end

function _M.redisGet(key)
    local red, err = getRedisConn()
    local value = nil
    if red then
        value, err = red:get(key)
        if not value then
            ngx.log(ngx.ERR, "failed to get key: " .. key .. " "  .. err .. "\n", err)
            return value, err
        end
        if value == ngx.null then
            value = nil
        end
        closeRedisConn(red)
    end
    return value, err
end

function _M.redisIncr(key)
    local red, err = getRedisConn()
    local res = 1
    if red then
        res, err = red:incr(key)
        if not res then
            ngx.log(ngx.ERR, "failed to incr key: " .. key .. " " .. err .. "\n", err)
        end
        closeRedisConn(red)
    end
    return res, err
end

function _M.redisBFAdd(value)
    local red, err = getRedisConn()
    local res = nil
    if red then
        -- call BF.ADD command with the prefix 'bf'
        res, err = red:bf():add(filterName, value)
        if not res then
            ngx.log(ngx.ERR, "bf():add value: " .. value .. " " .. err .. "\n", err)
            return res, err
        end

        closeRedisConn(red)
    end
    return res, err
end

function _M.redisBFExists(value)
    local red, err = getRedisConn()
    local res = nil
    if red then
        -- call BF.EXISTS command
        res, err = red:bf():exists(filterName, value)
        if not res then
            ngx.log(ngx.ERR, "bf():exists value: " .. value .. " " .. err .. "\n", err)
            return res, err
        elseif res == 1 then
            closeRedisConn(red)
            return true
        else
            closeRedisConn(red)
            return false
        end
    end
    return false
end

return _M