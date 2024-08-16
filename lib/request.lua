-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

local file_utils = require "file_utils"

local ngxfind = ngx.re.find
local ngxmatch = ngx.re.match
local ngxgmatch = ngx.re.gmatch
local sub = string.sub
local randomseed = math.randomseed
local random = math.random
local ostime = os.time
local osdate = os.date
local osclock = os.clock

local read_file_to_string = file_utils.read_file_to_string

local _M = {}

-- 生成一个随机的id
function _M.generate_id()
    local now = ostime()
    randomseed(now + (ngx.worker.id() + 1) * osclock() + random())
    local num = random(100000, 999999)

    return osdate("%Y%m%d%H%M%S", now) .. num
end

function _M.get_boundary()
    local content_type = ngx.var.http_content_type
    if not content_type then
        return nil, "no Content-Type"
    end
    local boundary = nil

    if content_type then
        local from, to = ngxfind(content_type, "\\s*boundary\\s*=\\s*(\\S+)", "isjo", nil, 1)
        if from then
            boundary = sub(content_type, from, to)
        end
    end

    return boundary
end

function _M.get_request_body()
    local body_data = ngx.ctx.request_body
    if not body_data then
        ngx.req.read_body()
        body_data = ngx.req.get_body_data()
        if not body_data then
            local body_file = ngx.req.get_body_file()
            if body_file then
                body_data = read_file_to_string(body_file, true)
            end
        end
        ngx.ctx.request_body = body_data
    end

    return body_data
end

function _M.get_post_args()
    ngx.req.read_body()
    return ngx.req.get_post_args()
end

function _M.get_upload_files()
    local boundary = _M.get_boundary()
    if not boundary then
        return nil, "no boundary"
    end

    local delimiter = '--' .. boundary .. '\r\n'
    local delimiter_end = '--' .. boundary .. '--' .. '\r\n'

    local content = ''
    local is_file = false

    local body_raw = _M.get_request_body()
    local it, err = ngxgmatch(body_raw, ".+?(?:\n|$)", "isjo")
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

        if line == delimiter or line == delimiter_end then
            if content ~= '' then
                if is_file then
                    is_file = false
                    files[name] = {content = content, fileName = fileName, ext = ext}
                end
               content = ''
            end
        elseif line ~= '\r\n' then
            if is_file then
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
                    is_file = true
                end
            end
        end
    end

    return files
end

return _M
