local redis = require "resty.redis"
local config = require "config"
-- register the module prefix "bf" for RedisBloom
-- redis.register_module_prefix("bf")

local tonumber = tonumber
local tostring = tostring
local ipairs = ipairs
local ngxmatch = ngx.re.match

local _M = {}

local host = config.get("redis_host")
local port = tonumber(config.get("redis_port")) or 6379
local passwd = config.get("redis_passwd")
local poolSize = config.get("redis_pool_size")

local redis_timeouts = config.get("redis_timeouts")
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

local redisSSL = config.get("redis_ssl")
--local filterName = "blackIpFilter"

local function getRedisConn()
    local red, err1 = redis:new()
    if not red then
        ngx.log(ngx.ERR, "failed to new redis:", err1)
        return nil, err1
    end

    red:set_timeouts(connect_timeout, send_timeout, read_timeout)

    local ok, err = red:connect(host, port, { ssl = redisSSL, pool_size = poolSize })

    if not ok then
        ngx.log(ngx.ERR, "failed to connect: ", err .. "\n")
        return nil, err
    end

    if passwd ~= nil and #passwd ~= 0 then
        local times = 0
        times, err = red:get_reused_times()

        if times == 0 then
            local res, err2 = red:auth(passwd)
            if not res then
                ngx.log(ngx.ERR, "failed to authenticate: ", err2)
                return nil, err2
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
        ngx.log(ngx.ERR, "failed to set keepalive: ", err)
        return
    end
end

function _M.redisSet(key, value, expireTime)
    local red, _ = getRedisConn()
    if red then
        local ok, err1 = red:set(key, value)
        if not ok then
            ngx.log(ngx.ERR, "failed to set key: " .. key .. " ", err1)
            return ok, err1
        elseif expireTime and expireTime > 0 then
            red:expire(key, expireTime)
        end

        closeRedisConn(red)
    end
end

function _M.redisBathSet(keyTable, value, keyPrefix)
    local red, _ = getRedisConn()
    if red then
        red:init_pipeline()

        if keyPrefix then
            for _, ip in ipairs(keyTable) do
                red:set(keyPrefix .. ip, value)
            end
        else
            for _, ip in ipairs(keyTable) do
                red:set(ip, value)
            end
        end

        local results, err = red:commit_pipeline()
        if not results then
            ngx.log(ngx.ERR, "failed to set keys: ", err)
            return results, err
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
            ngx.log(ngx.ERR, "failed to get key: " .. key, err)
            return value, err
        end
        if value == ngx.null then
            value = nil
        end
        closeRedisConn(red)
    end
    return value, err
end

function _M.redisIncr(key, expireTime)
    local red, err = getRedisConn()
    local res = 1
    if red then
        res, err = red:incr(key)
        if not res then
            ngx.log(ngx.ERR, "failed to incr key: " .. key, err)
        elseif res == 1 and expireTime and expireTime > 0 then
            red:expire(key, expireTime)
        end
        closeRedisConn(red)
    end
    return res, err
end

--[[
function _M.redisBFAdd(value)
    local red, err = getRedisConn()
    local res = nil
    if red then
        -- call BF.ADD command with the prefix 'bf'
        res, err = red:bf():add(filterName, value)
        if not res then
            ngx.log(ngx.ERR, "bf():add value: " .. value, err)
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
            ngx.log(ngx.ERR, "bf():exists value: " .. value, err)
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
]]
return _M
