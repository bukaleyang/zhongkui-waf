-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local geoip = require "geoip"
local config = require "config"
local lib = require "lib"
local ip_utils = require "ip_utils"
local request = require "request"
local stringutf8 = require "stringutf8"

local default_if_blank = stringutf8.default_if_blank
local generate_id = request.generate_id
local is_site_option_on = config.is_site_option_on
local get_client_ip = ip_utils.get_client_ip

local function init()
    local ctx = ngx.ctx

    local ip = get_client_ip()
    ctx.ip = ip

    ctx.ua = default_if_blank(ngx.var.http_user_agent, '')

    ctx.geoip = geoip.lookup(ip)

    ctx.request_id = generate_id()

    ctx.server_name = default_if_blank(ngx.var.server_name, 'unknown')
end

if is_site_option_on("waf") then

    init()

    lib.is_white_ip()

    lib.is_black_ip()

    lib.is_unsafe_http_method()

    lib.is_bot()

    lib.is_acl()

    lib.is_cc()

    lib.is_white_url()

    lib.is_black_url()

    lib.is_evil_args()

    lib.is_evil_headers()

    lib.is_evil_cookies()

    lib.is_evil_request_body()

end
