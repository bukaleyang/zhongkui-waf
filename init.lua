-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local config = require "config"

local scriptPath = debug.getinfo(1, 'S').source:sub(2)
local scriptDir = scriptPath:match("(.*[/\\])")
config.ZHONGKUI_PATH = scriptDir:sub(1, -2) or "/usr/local/openresty/zhongkui-waf"
config.CONF_PATH = config.ZHONGKUI_PATH .. "/conf"

config.loadConfigFile()
