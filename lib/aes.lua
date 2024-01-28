-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local aes = require "resty.aes"
local str = require "resty.string"

local tonumber = tonumber
local gsub = string.gsub
local char = string.char


local _M = {}

local function from_hex(s)
    return (gsub(s, '..', function(cc)
        return char(tonumber(cc, 16))
    end))
end

function _M.encrypt(key, msg, salt)
    local aes_128_cbc_md5 = aes:new(key, salt)
    local encrypted = aes_128_cbc_md5:encrypt(msg)
    return str.to_hex(encrypted)
end

function _M.decrypt(key, msg, salt)
    local aes_128_cbc_md5 = aes:new(key, salt)
    local encrypted = from_hex(msg)
    return aes_128_cbc_md5:decrypt(encrypted)
end

return _M
