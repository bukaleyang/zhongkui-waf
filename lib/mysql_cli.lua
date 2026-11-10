-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local mysql = require "resty.mysql"
local config = require "config"

local _M = {}

local mysql_config = config.get_system_config("mysql")
local host = mysql_config.host
local port = mysql_config.port
local user = mysql_config.user
local password = mysql_config.password
local database = mysql_config.database
local poolSize = mysql_config.poolSize
local timeout = mysql_config.timeout or 1000

function _M.get_connection()
    local db, err = mysql:new()
    if not db then
        ngx.log(ngx.ERR, "failed to instantiate mysql: ", err)
        return nil, err
    end

    db:set_timeout(timeout)

    local ok, err, errcode, sql_state = db:connect{
        host = host,
        port = port or 3306,
        database = database,
        user = user,
        password = password,
        charset = "utf8mb4",
        -- 攻击日志按批 INSERT，大 body 可能超过 1MB，留足余量
        max_packet_size = 8 * 1024 * 1024,
        pool_size = poolSize or 10
    }

    if not ok then
        ngx.log(ngx.ERR, "failed to connect: ", err, ": ", errcode, " ", sql_state)
        return nil, err
    end

    return db, err
end

function _M.query(sql, rows, query_timeout)
    local db = _M.get_connection()
    if not db then
        return nil, "failed to connect"
    end

    -- DDL（大表建索引）可能远超过普通查询超时，允许调用方单独指定
    if query_timeout then
        db:set_timeout(query_timeout)
    end

    local res, err, errcode, sql_state = db:query(sql, rows)
    if not res then
        ngx.log(ngx.ERR, "bad result: ", err, ": ", errcode, ": ", sql_state, ".")
        -- 查询失败时连接不可再复用，直接关闭避免泄漏
        db:close()
        return nil, err
    end

    _M.close_connection(db)
    return res
end


function _M.close_connection(db)
    -- put it into the connection pool of size 100,
    -- with 10 seconds max idle timeout
    local ok, err = db:set_keepalive(10000, poolSize or 10)
    if not ok then
        ngx.log(ngx.ERR, "failed to set keepalive: ", err)
    end

    return ok, err
end


return _M
