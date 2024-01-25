local cjson = require "cjson"
local config = require "config"
local fileUtils = require "file"
local user = require "user"
local request = require "request"
local ruleUtils = require "lib.ruleUtils"

local x509 = require "openssl.x509"

local pairs = pairs
local tostring = tostring
local tabinsert = table.insert
local ngxfind = ngx.re.find
local date = os.date

local _M = {}

local CERTIFICATE_PATH = config.rulePath .. "certificate.json"
local CERTS_PATH = config.ZHONGKUI_PATH .. "/admin/ssl-certs/"

local REGEX_CERT_PATH = "^" .. CERTS_PATH .. "\\S+\\.(?:pem|crt)$"
local REGEX_KEY_PATH = "^" .. CERTS_PATH .. "\\S+\\.key$"


function _M.doRequest()
    local response = {code = 200, data = {}, msg = ""}
    local uri = ngx.var.uri
    local reload = false

    if user.checkAuthToken() == false then
        response.code = 401
        response.msg = "User not logged in"
        ngx.status = 401
        ngx.say(cjson.encode(response))
        ngx.exit(401)
        return
    end

    if uri == "/certificate/list" then
        -- 查询证书列表
        response = ruleUtils.listRules(CERTIFICATE_PATH)
    elseif uri == "/certificate/save" then
        -- 修改或新增证书
        local newRule = ruleUtils.getRuleFromRequest()
        if not newRule then
            response.code = 500
            return
        end
        local publicKey = newRule.publicKey
        local privateKey = newRule.privateKey

        if not publicKey or not privateKey then
            response.code = 500
            ngx.say(cjson.encode(response))
            return
        end

        -- 解析证书
        local cert = x509.new(publicKey)

        local subject = cert:getSubject()
        local issuer = cert:getIssuer()
        local subjectAlt = cert:getSubjectAlt()
        local serial = cert:getSerial()
        local startTime, endTime = cert:getLifetime()

        newRule.serial = tostring(serial)
        newRule.effectiveDate = date("%Y-%m-%d", startTime)
        newRule.expirationDate = date("%Y-%m-%d", endTime)

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

        newRule.domainName = domainName

        local issuerName = ""
        local issuerOrgName = ""
        for key, value in pairs(issuer) do
            if key == "CN" then
                issuerName = value
            elseif key == "O" then
                issuerOrgName = value
            end
        end

        newRule.issuerName = issuerName
        newRule.issuerOrgName = issuerOrgName

        local ext = ".crt"
        if ngxfind(publicKey, "-----BEGIN CERTIFICATE-----", "jo") ~= nil then
            ext = ".pem"
        end

        local fileName = CERTS_PATH .. date("%Y%m%d%H%M%S") .. "_" .. domainName
        local certPath = fileName .. ext
        local keyPath = fileName.. ".key"

        -- 保存证书和私钥文件
        fileUtils.writeStringToFile(certPath, publicKey)
        fileUtils.writeStringToFile(keyPath, privateKey)

        newRule.certPath = certPath
        newRule.keyPath = keyPath

        newRule.publicKey = nil
        newRule.privateKey = nil
        newRule.file = nil

        response.data = cjson.encode(newRule)

        response = ruleUtils.saveOrUpdateRule(CERTIFICATE_PATH, newRule)
        reload = true
    elseif uri == "/certificate/remove" then
        response = ruleUtils.getRule(CERTIFICATE_PATH)
        local cert = response.data
        if cert then
            -- 删除证书
            response = ruleUtils.deleteRule(CERTIFICATE_PATH)

            -- 如果配置删除成功则删除证书和密钥文件
            if response and response.code == 200 then
                local certPath = cert.certPath
                local keyPath = cert.keyPath

                -- 删除前检查文件路径是否正确，避免删错造成严重后果
                if ngxfind(certPath, REGEX_CERT_PATH, "jo") then
                    fileUtils.removeFile(certPath)
                end

                if ngxfind(keyPath, REGEX_KEY_PATH, "jo") then
                    fileUtils.removeFile(keyPath)
                end
            end

            reload = true
        else
            response.code = 500
            response.msg = "crt not exists"
        end
    elseif uri == "/certificate/get" then
        -- 查询证书
        response = ruleUtils.getRule(CERTIFICATE_PATH)
        if response.code == 200 then
            local cert = response.data
            if cert then
                local publicKey = fileUtils.readFileToString(cert.certPath)
                local privateKey = fileUtils.readFileToString(cert.keyPath)

                response.data = {id = cert.id, publicKey = publicKey, privateKey = privateKey}
            end
        end
    elseif uri == "/certificate/readfile" then
        -- 读取证书或私钥文件中的内容

        local files, err = request.getUploadFiles()
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
    elseif uri == "/certificate/listcerts" then
        local json = fileUtils.readFileToString(CERTIFICATE_PATH)
        if json then
            local ruleTable = cjson.decode(json)
            local rules = ruleTable.rules

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

    ngx.say(cjson.encode(response))

    -- 如果没有错误且需要重载配置文件则重载配置文件
    if response.code == 200 and reload == true then
        config.reloadConfigFile()
    end
end

_M.doRequest()

return _M
