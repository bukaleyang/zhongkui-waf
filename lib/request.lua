-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

local fileUtils = require "file"

local ngxfind = ngx.re.find
local ngxmatch = ngx.re.match
local ngxgmatch = ngx.re.gmatch
local sub = string.sub
local randomseed = math.randomseed
local random = math.random
local ostime = os.time
local osdate = os.date

local _M = {}

function _M.generateId()
    local now = ostime()
    randomseed(now)
    local num = random(100000, 999999)

    return osdate("%Y%m%d%H%M%S", now) .. num
end

function _M.getBoundary()
    local contentType = ngx.var.http_content_type
    if not contentType then
        return nil, "no Content-Type"
    end
    local boundary = nil

    if contentType then
        local bfrom, bto = ngxfind(contentType, "\\s*boundary\\s*=\\s*(\\S+)", "isjo", nil, 1)
        if bfrom then
            boundary = sub(contentType, bfrom, bto)
        end
    end

    return boundary
end

function _M.getRequestBody()
    ngx.req.read_body()
    local bodyData = ngx.req.get_body_data()
    if not bodyData then
        local bodyFile = ngx.req.get_body_file()
        if bodyFile then
            bodyData = fileUtils.readFileToString(bodyFile, true)
        end
    end

    return bodyData
end

function _M.getUploadFiles()
    local boundary = _M.getBoundary()
    if not boundary then
        return nil, "no boundary"
    end

    local delimiter = '--' .. boundary .. '\r\n'
    local delimiterEnd = '--' .. boundary .. '--' .. '\r\n'

    local content = ''
    local isFile = false

    local bodyRaw = _M.getRequestBody()
    local it, err = ngxgmatch(bodyRaw, ".+?(?:\n|$)", "isjo")
    if not it then
        ngx.log(ngx.ERR, "error: ", err)
        return nil, err
    end

    local files = {}
    local name = nil
    local fileName = nil
    local ext = nil

    while true do
        local m, err = it()
        if err then
            ngx.log(ngx.ERR, "error: ", err)
            return nil, err
        end

        if not m then
            break
        end

        local line = m[0]
        if line == nil then
            break
        end

        if line == delimiter or line == delimiterEnd then
            if content ~= '' then
                if isFile then
                    isFile = false
                    files[name] = {content = content, fileName = fileName, ext = ext}
                end
               content = ''
            end
        elseif line ~= '\r\n' then
            if isFile then
                if content == '' then
                    local from = ngxfind(line, "Content-Type:\\s*\\S+/\\S+", "ijo")
                    if not from then
                        content = content .. line
                    end
                else
                    content = content .. line
                end
            else
                local from, to = ngxfind(line, [[Content-Disposition:\s*form-data;\s*name=["|']\w+["|'];\s*filename=["|'][\s\S]+\.\w+(?:"|')]], "ijo")
                if from then
                    name = sub(line, from, to)

                    local ma, _ = ngxmatch(line, [[Content-Disposition:\s*form-data;\s*name=["|'](\w+)["|'];\s*filename=["|']([\s\S]+)(\.\w+)(?:"|')]], "ijo")
                    if ma then
                        name = ma[1]
                        ext = ma[3]
                        fileName = ma[2] .. ext
                    end
                    isFile = true
                end
            end
        end
    end

    return files
end

return _M
