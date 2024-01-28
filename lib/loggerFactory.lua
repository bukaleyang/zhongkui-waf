-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local logger = require "logger"

local loggers = {}

local _M = {}

function _M.getLogger(logPath, host, rolling)
    local hostLogger = loggers[host]
    if not hostLogger then
        hostLogger = logger:new(logPath, host, rolling)
        loggers[host] = hostLogger
    end
    return hostLogger
end


return _M