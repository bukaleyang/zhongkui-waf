-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

local _M = {}

_M.KEY_HTTP_4XX = 'http4x'
_M.KEY_HTTP_5XX = 'http5x'
_M.KEY_REQUEST_TIMES = 'request_times'
_M.KEY_ATTACK_TIMES = 'attack_times'
_M.KEY_BLOCK_TIMES = 'block_times'
_M.KEY_ATTACK_PREFIX = 'attack_'
_M.KEY_ATTACK_TYPE_PREFIX = 'attack_type_'
_M.KEY_ATTACK_LOG = 'attack_log'
_M.KEY_IP_BLOCK_LOG = 'ip_block_log'
_M.KEY_BLACKIP_PREFIX = 'black_ip:'
_M.KEY_IP_GROUPS_WHITELIST = 'ipWhiteList'
_M.KEY_IP_GROUPS_BLACKLIST = 'ipBlackList'

return _M
