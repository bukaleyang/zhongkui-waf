-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

local file_utils = require "file_utils"
local upload = require "upload"

local ngxmatch = ngx.re.match
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

-- 返回单个 Content-Type 值；重复头或含多个 media type 时返回 nil + 原因。
-- 重复/逗号合并的 Content-Type 会让 WAF 与后端看到不同的解析结果，按异常处理。
function _M.get_content_type()
    local headers = ngx.req.get_headers()
    local content_type = headers["content-type"]

    if type(content_type) == "table" then
        if #content_type > 1 then
            return nil, "duplicate_content_type"
        end
        content_type = content_type[1]
    end

    if content_type == nil or content_type == "" then
        return nil, "no Content-Type"
    end

    if upload.content_type_is_ambiguous(content_type) then
        return nil, "ambiguous_content_type"
    end

    return content_type
end

-- 只从 multipart/form-data 的 Content-Type 里取 boundary。
-- quoted-string 形式会剥掉引号：boundary="----X" 的分隔符是 --X。
-- 同时按 RFC 2046 校验 boundary 字符集/长度，非法值返回错误，交给上层 fail-closed。
function _M.get_boundary()
    local content_type, content_type_err = _M.get_content_type()
    if not content_type then
        return nil, content_type_err
    end

    if not ngxmatch(content_type, [[^\s*multipart/]], "ijo") then
        return nil, "not multipart"
    end

    -- 只解析 multipart/form-data；其他 multipart 子类型（mixed/related 等）
    -- 的嵌套结构可能与后端解析不一致，交给上层 fileExt fail-closed 处理
    if not ngxmatch(content_type, [[^\s*multipart/form-data\b]], "ijo") then
        return nil, "unsupported multipart subtype"
    end

    -- boundary 只能出现一次：重复 boundary 时 WAF 与后端可能各取一个，
    -- 攻击者可以用两个 boundary 拼出“WAF 看安全、后端看恶意”的请求，直接拒绝
    local count = 0
    local it, it_err = ngx.re.gmatch(content_type, [[(?:^|;)\s*boundary\s*=]], "ijo")
    if not it then
        ngx.log(ngx.ERR, "boundary gmatch error: ", it_err)
        return nil, "invalid boundary"
    end

    while true do
        local m, err = it()
        if err then
            ngx.log(ngx.ERR, "boundary gmatch error: ", err)
            return nil, "invalid boundary"
        end
        if not m then
            break
        end

        count = count + 1
        if count > 1 then
            return nil, "duplicate boundary"
        end
    end

    local m = ngxmatch(content_type,
        [[(?:^|;)\s*boundary\s*=\s*(?:"([^"]*)"|([^;\s]+))]], "ijo")
    if not m then
        return nil, "no boundary"
    end

    local boundary = m[1] or m[2]
    if not boundary or boundary == "" then
        return nil, "empty boundary"
    end

    if not upload.validate_boundary(boundary) then
        return nil, "invalid boundary"
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

    local body_raw = _M.get_request_body()
    if not body_raw then
        return nil, "no body"
    end

    local files = {}

    -- 复用 upload.scan_multipart：同一套解析逻辑，避免 WAF 与后台读取文件
    -- 对 filename/filename*/空 part 的理解不一致
    upload.scan_multipart(body_raw, boundary, {
        -- body 已经在内存里，后台读取文件（证书/私钥）需要完整内容
        max_file_content = #body_raw,

        on_file = function(content, cd)
            if not cd or not cd.name then
                return false
            end

            local names = upload.candidate_filenames(cd)
            local file_name = names[1] or cd.filename or ""

            -- 去掉客户端带上的路径（IE 会发送完整路径）
            file_name = file_name:match("[^/\\]+$") or file_name

            local ext = upload.get_extension(file_name)

            files[cd.name] = {
                content = content,
                fileName = file_name,
                ext = ext and ("." .. ext) or ""
            }

            return false
        end
    })

    return files
end

return _M
