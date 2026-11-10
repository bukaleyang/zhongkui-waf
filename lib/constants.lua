-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

local _M = {}

_M.KEY_HTTP_4XX = 'http4x'
_M.KEY_HTTP_5XX = 'http5x'
_M.KEY_REQUEST_TIMES = 'request_times'
_M.KEY_ATTACK_TIMES = 'attack_times'
_M.KEY_BLOCK_TIMES_ATTACK = 'block_times_attack'
_M.KEY_BLOCK_TIMES_CAPTCHA = 'block_times_captcha'
_M.KEY_BLOCK_TIMES_CC = 'block_times_cc'
_M.KEY_CAPTCHA_PASS_TIMES = 'captcha_pass_times'
_M.KEY_ATTACK_PREFIX = 'attack_'
_M.KEY_ATTACK_TYPE_PREFIX = 'attack_type_'
_M.KEY_BLOCKED_PREFIX = 'blocked_'
_M.KEY_ATTACK_LOG = 'attack_log'
_M.KEY_IP_BLOCK_LOG = 'ip_block_log'
_M.KEY_BLACKIP_PREFIX = 'black_ip:'
_M.KEY_IP_GROUPS_WHITELIST = 'ipWhiteList'
_M.KEY_IP_GROUPS_BLACKLIST = 'ipBlackList'
_M.KEY_CAPTCHA_PREFIX = 'captcha:'
_M.KEY_CAPTCHA_ACCESSTOKEN_REDIS_PREFIX = 'captcha_accesstoken:'

-- 写入 attack_log 的内容上限默认值，可在 conf/system.json 的 logLimit 中覆盖
-- 请求体：覆盖常见 JSON/表单/上传片段，避免单行过大
_M.DEFAULT_MAX_REQUEST_BODY_LEN = 256 * 1024
-- 响应体：与 ModSecurity / Coraza 的 SecResponseBodyLimit 默认值（512KB）一致
_M.DEFAULT_MAX_RESPONSE_BODY_LEN = 512 * 1024
-- header：常见服务器单个 header 上限是 8KB，整体 16KB 足够定位问题
_M.DEFAULT_MAX_HEADER_LEN = 16 * 1024
-- 单个字段允许配置的最大值，保证单行和批量 INSERT 不超过 mysql_cli.max_packet_size
_M.MAX_LOG_FIELD_LEN = 1024 * 1024

return _M
