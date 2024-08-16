-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local config = require "config"

local script_path = debug.getinfo(1, 'S').source:sub(2)
local script_dir = script_path:match("(.*[/\\])")
config.ZHONGKUI_PATH = script_dir:sub(1, -2) or "/usr/local/openresty/zhongkui-waf"
config.CONF_PATH = config.ZHONGKUI_PATH .. "/conf"

config.load_config_file()
