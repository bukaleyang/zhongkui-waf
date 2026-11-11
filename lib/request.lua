-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

local file_utils = require "file_utils"

local ngxfind = ngx.re.find
local ngxmatch = ngx.re.match
local sub = string.sub
local find_plain = string.find
local insert = table.insert
local concat = table.concat
local format = string.format
local ostime = os.time
local osdate = os.date

local read_file_to_string = file_utils.read_file_to_string

local _M = {}

-- 生成一个随机的id
local seq = 0

function _M.generate_id()
    seq = seq + 1
    local worker_id = ngx.worker.id() or 0
    -- worker 前缀 + 自增序号，避免每次请求 randomseed 的开销和同秒重复
    return osdate("%Y%m%d%H%M%S", ostime()) .. format("%02d%04d", worker_id % 100, seq % 10000)
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

    local body_raw = _M.get_request_body()
    if not body_raw then
        return nil, "no body"
    end

    local total_len = #body_raw
    local chunks = {}
    local is_file = false
    local pos = 1

    local files = {}
    local name = nil
    local fileName = nil
    local ext = nil

    -- 逐行扫描：字面量查找 + table 收集，避免大文件上 content = content .. line 的 O(n²)
    while pos <= total_len do
        local nl = find_plain(body_raw, '\n', pos, true)
        local line

        if nl then
            line = sub(body_raw, pos, nl)      -- 保留行尾 \n，与原来的逐行匹配结果一致
            pos = nl + 1
        else
            line = sub(body_raw, pos)
            pos = total_len + 1
        end

        if line == delimiter or line == delimiter_end then
            if #chunks > 0 then
                if is_file then
                    is_file = false
                    files[name] = {content = concat(chunks), fileName = fileName, ext = ext}
                end
                chunks = {}
            end
        elseif line ~= '\r\n' then
            if is_file then
                if #chunks == 0 then
                    local from = ngxfind(line, "Content-Type:\\s*\\S+/\\S+", "ijo")
                    if not from then
                        insert(chunks, line)
                    end
                else
                    insert(chunks, line)
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
