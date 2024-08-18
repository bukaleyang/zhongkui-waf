-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

local cjson = require "cjson"
local config = require "config"
local file_utils = require "file_utils"
local user = require "user"
local request = require "request"
local rule_utils = require "lib.rule_utils"
local has_x509, x509 = pcall(require, "openssl.x509")

local pairs = pairs
local tostring = tostring
local error = error
local tabinsert = table.insert
local ngxfind = ngx.re.find
local date = os.date
local get_upload_files = request.get_upload_files
local read_file_to_string = file_utils.read_file_to_string
local remove_file = file_utils.remove_file

local cjson_decode = cjson.decode
local cjson_encode = cjson.encode

local _M = {}

local CERTIFICATE_PATH = config.CONF_PATH .. "/certificate.json"
local CERTS_PATH = config.ZHONGKUI_PATH .. "/admin/ssl-certs/"

local REGEX_CERT_PATH = "^" .. CERTS_PATH .. "\\S+\\.(?:pem|crt)$"
local REGEX_KEY_PATH = "^" .. CERTS_PATH .. "\\S+\\.key$"


function _M.do_request()
    local response = {code = 200, data = {}, msg = ""}
    local uri = ngx.var.uri
    local reload = false

    if user.check_auth_token() == false then
        response.code = 401
        response.msg = "User not logged in"
        ngx.status = 401
        ngx.say(cjson_encode(response))
        ngx.exit(401)
        return
    end

    if uri == "/common/certificate/list" then
        -- 查询证书列表
        response = rule_utils.list_rules(CERTIFICATE_PATH)
    elseif uri == "/common/certificate/save" then
        -- 修改或新增证书
        local rule_new = rule_utils.get_rule_from_request()
        if not rule_new then
            response.code = 500
            return
        end
        local publicKey = rule_new.publicKey
        local privateKey = rule_new.privateKey

        if not publicKey or not privateKey then
            response.code = 500
            ngx.say(cjson_encode(response))
            return
        end

        if not has_x509 then
            error("certificate parsing failed because openssl.x509 is not installed", 2)
        end

        -- 解析证书
        local cert = x509.new(publicKey)

        local subject = cert:getSubject()
        local issuer = cert:getIssuer()
        local subjectAlt = cert:getSubjectAlt()
        local serial = cert:getSerial()
        local start_time, end_time = cert:getLifetime()

        rule_new.serial = tostring(serial)
        rule_new.effectiveDate = date("%Y-%m-%d", start_time)
        rule_new.expirationDate = date("%Y-%m-%d", end_time)

        local domainName = nil

        for key, value in pairs(subjectAlt) do
            if key == "CN" then
                domainName = value
                break
            end
        end

        if not domainName then
            for key, value in pairs(subject) do
                if key == "CN" then
                    domainName = value
                    break
                end
            end
        end

        rule_new.domainName = domainName

        local issuerName = ""
        local issuerOrgName = ""
        for key, value in pairs(issuer) do
            if key == "CN" then
                issuerName = value
            elseif key == "O" then
                issuerOrgName = value
            end
        end

        rule_new.issuerName = issuerName
        rule_new.issuerOrgName = issuerOrgName

        local ext = ".crt"
        if ngxfind(publicKey, "-----BEGIN CERTIFICATE-----", "jo") ~= nil then
            ext = ".pem"
        end

        local fileName = CERTS_PATH .. date("%Y%m%d%H%M%S") .. "_" .. domainName
        local certPath = fileName .. ext
        local keyPath = fileName.. ".key"

        -- 保存证书和私钥文件
        file_utils.write_string_to_file(certPath, publicKey)
        file_utils.write_string_to_file(keyPath, privateKey)

        rule_new.certPath = certPath
        rule_new.keyPath = keyPath

        rule_new.publicKey = nil
        rule_new.privateKey = nil
        rule_new.file = nil

        response = rule_utils.save_or_update_rule(CERTIFICATE_PATH, rule_new)
        reload = true
    elseif uri == "/common/certificate/remove" then
        response = rule_utils.get_rule(CERTIFICATE_PATH)
        local cert = response.data
        if cert then
            -- 删除证书
            response = rule_utils.delete_rule(CERTIFICATE_PATH)

            -- 如果配置删除成功则删除证书和密钥文件
            if response and response.code == 200 then
                local certPath = cert.certPath
                local keyPath = cert.keyPath

                -- 删除前检查文件路径是否正确，避免删错造成严重后果
                if ngxfind(certPath, REGEX_CERT_PATH, "jo") then
                    remove_file(certPath)
                end

                if ngxfind(keyPath, REGEX_KEY_PATH, "jo") then
                    remove_file(keyPath)
                end
            end

            reload = true
        else
            response.code = 500
            response.msg = "crt not exists"
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
                    local certName = r.domainName .. "(" .. r.issuerName .. ")"
                    local cert = {id = r.id, certName = certName }
                    tabinsert(certs, cert)
                end
            end

            response.data = certs
        end
    end

    ngx.say(cjson_encode(response))

    -- 如果没有错误且需要重载配置文件则重载配置文件
    if response.code == 200 and reload == true then
        config.reload_config_file()
    end
end

_M.do_request()

return _M
