-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

local timerat = ngx.timer.at
local every = ngx.timer.every

local _M = {}

function _M.startTimer(delay, callback)
    local ok, err = timerat(delay, callback)
    if not ok then
        ngx.log(ngx.ERR, "failed to create timer: ", err)
        return
    end

    return ok, err
end

function _M.startTimerEvery(delay, callback)
    local ok, err = every(delay, callback)
    if not ok then
        ngx.log(ngx.ERR, "failed to create the timer: ", err)
        return
    end

    return ok, err
end

function _M.dictIncr(dict, key, ttl)
    local newval, err = dict:incr(key, 1)
    if not newval then
        if ttl then
            local t = type(ttl)
            if t == 'number' then
                dict:set(key, 1, ttl)
            elseif t == 'function' then
                dict:set(key, 1, ttl())
            end
        else
            dict:set(key, 1)
        end

        return 1
    end

    return newval, err
end

function _M.dictSet(dict, key, value, ttl)
    return dict:set(key, value, ttl)
end

function _M.dictGet(dict, key)
    return dict:get(key)
end

return _M
