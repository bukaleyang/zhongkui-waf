-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local mysql = require "resty.mysql"
local config = require "config"


local tonumber = tonumber
local tostring = tostring
local ipairs = ipairs
local ngxmatch = ngx.re.match

local _M = {}

local host = config.get("mysql_host")
local port = tonumber(config.get("mysql_port")) or 3306
local database = config.get("mysql_database")
local user = config.get("mysql_user")
local password = config.get("mysql_password")
local poolSize = tonumber(config.get("mysql_pool_size")) or 10
local timeout = tonumber(config.get("mysql_timeout")) or 1000


function _M.getConnection()
    local db, err = mysql:new()
    if not db then
        ngx.log(ngx.ERR, "failed to instantiate mysql: ", err)
        return nil, err
    end

    db:set_timeout(timeout)

    local ok, err, errcode, sqlstate = db:connect{
        host = host,
        port = port,
        database = database,
        user = user,
        password = password,
        charset = "utf8mb4",
        max_packet_size = 1024 * 1024,
        pool_size = poolSize
    }

    if not ok then
        ngx.log(ngx.ERR, "failed to connect: ", err, ": ", errcode, " ", sqlstate)
        return nil, err
    end

    return db, err
end

function _M.query(sql, rows)
    local res, err, errcode, sqlstate
    local db = _M.getConnection()
    if db then
        res, err, errcode, sqlstate = db:query(sql, rows)
        if not res then
            ngx.log(ngx.ERR, "bad result: ", err, ": ", errcode, ": ", sqlstate, ".")
            return
        end

        _M.closeConnection(db)
    end

    return res
end


function _M.closeConnection(db)
    -- put it into the connection pool of size 100,
    -- with 10 seconds max idle timeout
    local ok, err = db:set_keepalive(10000, poolSize)
    if not ok then
        ngx.log(ngx.ERR, "failed to set keepalive: ", err)
    end

    return ok, err
end


return _M
