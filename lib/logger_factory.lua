-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local logger = require "logger"

local loggers = {}

local _M = {}

function _M.get_logger(logPath, host, rolling)
    local host_logger = loggers[host]
    if not host_logger then
        host_logger = logger:new(logPath, host, rolling)
        loggers[host] = host_logger
    end
    return host_logger
end

return _M