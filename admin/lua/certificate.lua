-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

local cjson = require "cjson"
local config = require "config"
local file_utils = require "file_utils"
local user = require "user"
local request = require "request"
local rule_utils = require "lib.rule_utils"
local site_config = require "lib.site_config"
local x509 = require "lib.x509"
local acme = require "lib.acme"

local pairs = pairs
local tonumber = tonumber
local tostring = tostring
local pcall = pcall
local type = type
local gsub = string.gsub
local tabinsert = table.insert
local ngxfind = ngx.re.find
local date = os.date
local get_upload_files = request.get_upload_files
local read_file_to_string = file_utils.read_file_to_string
local write_string_to_file = file_utils.write_string_to_file
local remove_file = file_utils.remove_file
local is_file_exists = file_utils.is_file_exists

local cjson_decode = cjson.decode
local cjson_encode = cjson.encode

local _M = {}

local CERTIFICATE_PATH = config.CONF_PATH .. "/certificate.json"
local WEBSITES_PATH = config.CONF_PATH .. "/website.json"
local CERTS_PATH = (gsub(config.ZHONGKUI_PATH .. "/admin/ssl-certs/", "\\", "/"))

local CERT_EXTS = {pem = true, crt = true}
local KEY_EXTS = {key = true}

-- 校验文件路径是否在证书目录且扩展名正确，避免误删其它文件
local function is_safe_path(path, extensions)
    if not path then
        return false
    end

    path = gsub(path, "\\", "/")
    if path:sub(1, #CERTS_PATH) ~= CERTS_PATH then
        return false
    end

    local name = path:sub(#CERTS_PATH + 1)
    if name == "" or name:find("/", 1, true) or name:find("..", 1, true) then
        return false
    end

    local ext = name:match("%.([^.]+)$")
    return ext ~= nil and extensions[ext:lower()] == true
end

-- 域名中的特殊字符不能出现在文件名中，Windows 也不允许文件名带 *
local function safe_file_name(name)
    name = gsub(name or "unknown", "%*", "wildcard")
    return (gsub(name, "[^%w%.%-_]", "_"))
end

-- 查询证书是否被启用了 SSL 的站点引用，返回站点域名
local function get_cert_site(cert_id)
    local json = read_file_to_string(WEBSITES_PATH)
    if not json then
        return nil
    end

    local ok, rule_table = pcall(cjson_decode, json)
    if not ok or type(rule_table) ~= "table" or not rule_table.rules then
        return nil
    end

    cert_id = tonumber(cert_id)

    for _, site in pairs(rule_table.rules) do
        for _, p in pairs(site.listenPorts or {}) do
            if (p.ssl == "on" or p.ssl == true) and tonumber(site.certId) == cert_id then
                local names = site.serverNames
                return (names and names[1]) or ("id=" .. tostring(site.id))
            end
        end
    end

    return nil
end

function _M.do_request()
    local response = {code = 200, data = {}, msg = ""}
    local uri = ngx.var.uri
    local reload = false

    -- 本机调度器可免登录调用续期检查；公网访问仍需登录
    local is_local_renew = false
    if uri == "/common/certificate/acme/renew-due" then
        local ip = ngx.var.remote_addr or ""
        is_local_renew = ip == "127.0.0.1" or ip == "::1" or ip == "::ffff:127.0.0.1"
    end

    if not is_local_renew and user.check_auth_token() == false then
        response.code = 401
        response.msg = "User not logged in"
        ngx.status = 401
        ngx.say(cjson_encode(response))
        ngx.exit(401)
        return
    end

    if uri == "/common/certificate/acme/settings" then
        response = acme.settings_response()
    elseif uri == "/common/certificate/acme/apply" then
        local ok, field = pcall(rule_utils.get_rule_from_request)
        if not ok then
            response = {code = 400, msg = "请求参数格式错误"}
        else
            -- 兜底：ACME 内部任何未捕获的 Lua 错误都转成 JSON，避免前端收到 HTML 崩溃页
            local called, applied = pcall(acme.apply, field or {})
            if called then
                response = applied
            else
                ngx.log(ngx.ERR, "ACME apply crashed: ", tostring(applied))
                response = {code = 500, msg = "证书申请失败: " .. tostring(applied)}
            end
        end
    elseif uri == "/common/certificate/acme/renew" then
        local called, renewed = pcall(function()
            ngx.req.read_body()
            local args = ngx.req.get_post_args()
            return acme.renew(args and args.id, args and args.force == "1")
        end)
        if called then
            response = renewed
        else
            ngx.log(ngx.ERR, "ACME renew crashed: ", tostring(renewed))
            response = {code = 500, msg = "证书续期失败: " .. tostring(renewed)}
        end
    elseif uri == "/common/certificate/acme/renew-due" then
        local called, renewed = pcall(acme.renew_due)
        if called then
            response = renewed
        else
            ngx.log(ngx.ERR, "ACME renew-due crashed: ", tostring(renewed))
            response = {code = 500, data = {checked = 0, renewed = 0, failed = 0}, msg = ""}
        end
    elseif uri == "/common/certificate/list" then
        -- 查询证书列表
        response = rule_utils.list_rules(CERTIFICATE_PATH)
    elseif uri == "/common/certificate/save" then
        -- 修改或新增证书
        local rule_new = rule_utils.get_rule_from_request()
        if not rule_new then
            response.code = 500
            ngx.say(cjson_encode(response))
            return
        end

        local publicKey = rule_new.publicKey
        local privateKey = rule_new.privateKey

        if not publicKey or not privateKey then
            response.code = 500
            ngx.say(cjson_encode(response))
            return
        end

        -- 有 id 时先确认记录存在，避免写了文件却没有更新配置
        rule_new.id = tonumber(rule_new.id)
        local old_cert = nil

        if rule_new.id then
            old_cert = rule_utils.get_rule(CERTIFICATE_PATH, rule_new.id).data

            if not old_cert then
                response.code = 500
                response.msg = "certificate not found"
                ngx.say(cjson_encode(response))
                return
            end

            -- 免费证书由 ACME 管理，避免手动覆盖后失去自动续期能力
            if old_cert.source == "acme" or old_cert.acme ~= nil then
                response.code = 500
                response.msg = "免费证书不支持手动编辑，请使用续期或删除后重新申请"
                ngx.say(cjson_encode(response))
                return
            end
        end

        -- 解析证书
        local cert, cert_err = x509.parse(publicKey)
        if not cert then
            response.code = 500
            response.msg = "certificate parsing failed: " .. (cert_err or "invalid certificate")
            ngx.say(cjson_encode(response))
            return
        end

        local domainName = cert.domainName

        rule_new.serial = cert.serial
        rule_new.effectiveDate = cert.effectiveDate
        rule_new.expirationDate = cert.expirationDate
        rule_new.domainName = domainName
        rule_new.issuerName = cert.issuerName
        rule_new.issuerOrgName = cert.issuerOrgName

        local ext = ".crt"
        if ngxfind(publicKey, "-----BEGIN CERTIFICATE-----", "jo") ~= nil then
            ext = ".pem"
        end

        -- 同域名修改复用原文件路径，避免产生孤儿文件
        local reuse = old_cert ~= nil
            and old_cert.domainName == domainName
            and is_safe_path(old_cert.certPath, CERT_EXTS)
            and is_safe_path(old_cert.keyPath, KEY_EXTS)
            and is_file_exists(old_cert.certPath)
            and is_file_exists(old_cert.keyPath)

        local certPath, keyPath

        if reuse then
            certPath = old_cert.certPath
            keyPath = old_cert.keyPath
        else
            local fileName = CERTS_PATH .. date("%Y%m%d%H%M%S") .. "_" .. safe_file_name(domainName)
            certPath = fileName .. ext
            keyPath = fileName .. ".key"
        end

        -- 保存证书和私钥文件
        write_string_to_file(certPath, publicKey)
        write_string_to_file(keyPath, privateKey)

        if not is_file_exists(certPath) or not is_file_exists(keyPath) then
            response.code = 500
            response.msg = "failed to write certificate files"
            ngx.say(cjson_encode(response))
            return
        end

        rule_new.certPath = certPath
        rule_new.keyPath = keyPath
        rule_new.source = "manual"
        rule_new.acme = nil
        rule_new.autoRenew = nil

        rule_new.publicKey = nil
        rule_new.privateKey = nil
        rule_new.file = nil

        response = rule_utils.save_or_update_rule(CERTIFICATE_PATH, rule_new)

        -- 确认配置已更新，再删除旧文件
        local saved = rule_utils.get_rule(CERTIFICATE_PATH, rule_new.id).data

        if not saved or saved.certPath ~= certPath then
            response.code = 500
            response.msg = "failed to save certificate"

            if not reuse then
                remove_file(certPath)
                remove_file(keyPath)
            end
        else
            if old_cert and not reuse then
                if is_safe_path(old_cert.certPath, CERT_EXTS) then
                    remove_file(old_cert.certPath)
                end

                if is_safe_path(old_cert.keyPath, KEY_EXTS) then
                    remove_file(old_cert.keyPath)
                end
            end

            -- 证书文件可能刚恢复，重新生成站点配置并 reload
            local generated, generate_err = site_config.generate()
            if not generated then
                ngx.log(ngx.ERR, "failed to generate site config after certificate change: ", tostring(generate_err))
            end
            reload = true
        end
    elseif uri == "/common/certificate/remove" then
        -- 删除证书
        ngx.req.read_body()
        local args = ngx.req.get_post_args()
        local id = args and args['id']

        response = rule_utils.get_rule(CERTIFICATE_PATH, id)
        local cert = response.data

        if not cert then
            response.code = 500
            response.msg = "crt not exists"
        else
            local site = get_cert_site(cert.id)

            if site then
                -- 证书仍被启用 SSL 的站点引用，拒绝删除
                response.code = 500
                response.msg = "该证书正被站点 [" .. site .. "] 使用，请先解绑"
            else
                response = rule_utils.delete_rule(CERTIFICATE_PATH)

                -- 如果配置删除成功则删除证书和密钥文件
                if response.code == 200 then
                    if is_safe_path(cert.certPath, CERT_EXTS) then
                        remove_file(cert.certPath)
                    end

                    if is_safe_path(cert.keyPath, KEY_EXTS) then
                        remove_file(cert.keyPath)
                    end

                    acme.remove_cert_data(cert)
                end
            end
        end
    elseif uri == "/common/certificate/get" then
        -- 查询证书
        response = rule_utils.get_rule(CERTIFICATE_PATH)
        if response.code == 200 then
            local cert = response.data
            if cert then
                local publicKey = read_file_to_string(cert.certPath)
                local privateKey = read_file_to_string(cert.keyPath)

                response.data = {id = cert.id, publicKey = publicKey, privateKey = privateKey}
            end
        end
    elseif uri == "/common/certificate/readfile" then
        -- 读取证书或私钥文件中的内容

        local files, err = get_upload_files()
        if files then
            local file = files["file"]
            if file then
                response.data = file.content
            end
        else
            response.code = 500
            response.msg = err
            ngx.log(ngx.ERR, err)
        end
    elseif uri == "/common/certificate/listcerts" then
        local json = read_file_to_string(CERTIFICATE_PATH)
        if json then
            local rule_table = cjson_decode(json)
            local rules = rule_table.rules
            local certs = {}

            if rules then
                for _, r in pairs(rules) do
                    local certName = (r.domainName or "") .. "(" .. (r.issuerName or "") .. ")"
                    local cert = {id = r.id, certName = certName }
                    tabinsert(certs, cert)
                end
            end

            response.data = certs
        end
    end

    ngx.say(cjson_encode(response))

    -- 证书文件内容变化后重载 nginx
    if response.code == 200 and reload == true then
        local reloaded, reload_err = config.reload_config_file()
        if not reloaded then
            ngx.log(ngx.ERR, "failed to reload nginx after certificate change: ", tostring(reload_err))
        end
    end
end

_M.do_request()

return _M
