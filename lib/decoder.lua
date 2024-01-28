-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local _M = {}

function _M.decodeBase64(str)
    local newStr = str
    for t = 1, 2 do
        local temp = ngx.decode_base64(newStr)
        if not temp then
            break
        end
        newStr = temp
    end
    return newStr
end

function _M.unescapeUri(str)
    local newStr = str
    for t = 1, 2 do
        local temp = ngx.unescape_uri(newStr)
        if not temp then
            break
        end
        newStr = temp
    end
    return newStr
end

function _M.removeComment(str)
    if str == nil then return nil end
    local newStr, n, err = ngx.re.gsub(str, "/\\*[\\s\\S]*\\*/", " ", "ijo")
    return newStr
end


return _M
