-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local _M = {}

function _M.decode_base64(str)
    local str_new = str
    for t = 1, 2 do
        local temp = ngx.decode_base64(str_new)
        if not temp then
            break
        end
        str_new = temp
    end
    return str_new
end

function _M.unescape_uri(str)
    local str_new = str
    for t = 1, 2 do
        local temp = ngx.unescape_uri(str_new)
        if not temp then
            break
        end
        str_new = temp
    end
    return str_new
end

function _M.remove_comment(str)
    if str == nil then return nil end
    local str_new, n, err = ngx.re.gsub(str, "/\\*[\\s\\S]*\\*/", " ", "ijo")
    return str_new
end


return _M
