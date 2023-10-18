local config = require "config"

local scriptPath = debug.getinfo(1, 'S').source:sub(2)
local scriptDir = scriptPath:match("(.*[/\\])")
config.ZHONGKUI_PATH = scriptDir:sub(1, -2) or "/usr/local/openresty/zhongkui-waf"

config.loadConfigFile()
