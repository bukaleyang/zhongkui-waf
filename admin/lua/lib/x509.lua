-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

-- 通过 LuaJIT FFI 调用 OpenResty 内置 OpenSSL 解析 X.509 证书，
-- 避免依赖 Windows 上难以安装的 lua-openssl（openssl.x509）模块。

local ffi = require "ffi"
local ngx_ssl = require "ngx.ssl"

ffi.cdef[[
typedef struct x509_st X509;
typedef struct X509_name_st X509_NAME;
typedef struct X509_name_entry_st X509_NAME_ENTRY;
typedef struct asn1_string_st ASN1_STRING;
typedef struct asn1_string_st ASN1_INTEGER;
typedef struct asn1_string_st ASN1_TIME;
typedef struct bignum_st BIGNUM;

void *OPENSSL_sk_value(const void *st, int i);
X509_NAME *X509_get_subject_name(X509 *a);
X509_NAME *X509_get_issuer_name(X509 *a);
int X509_NAME_get_index_by_NID(X509_NAME *name, int nid, int lastpos);
X509_NAME_ENTRY *X509_NAME_get_entry(X509_NAME *name, int loc);
ASN1_STRING *X509_NAME_ENTRY_get_data(X509_NAME_ENTRY *ne);
int ASN1_STRING_to_UTF8(unsigned char **out, ASN1_STRING *in);
int ASN1_STRING_length(const ASN1_STRING *x);
const unsigned char *ASN1_STRING_get0_data(const ASN1_STRING *x);
ASN1_INTEGER *X509_get_serialNumber(X509 *x);
BIGNUM *ASN1_INTEGER_to_BN(const ASN1_INTEGER *ai, BIGNUM *bn);
char *BN_bn2dec(const BIGNUM *a);
void BN_free(BIGNUM *a);
void CRYPTO_free(void *ptr, const char *file, int line);
ASN1_TIME *X509_get0_notBefore(const X509 *x);
ASN1_TIME *X509_get0_notAfter(const X509 *x);
]]

local C = ffi.C
local format = string.format
local tonumber = tonumber
local type = type
local ffi_string = ffi.string

-- OpenSSL NID 常量
local NID_CN = 13
local NID_O = 17

local _M = {}

-- 读取 Name 中指定字段，转换为 UTF-8
local function get_name(name, nid)
    if name == nil then
        return nil
    end

    local index = C.X509_NAME_get_index_by_NID(name, nid, -1)
    if index < 0 then
        return nil
    end

    local entry = C.X509_NAME_get_entry(name, index)
    if entry == nil then
        return nil
    end

    local data = C.X509_NAME_ENTRY_get_data(entry)
    if data == nil then
        return nil
    end

    local out = ffi.new("unsigned char*[1]")
    local len = C.ASN1_STRING_to_UTF8(out, data)
    if len < 0 then
        return nil
    end

    local value = ffi_string(out[0], len)
    C.CRYPTO_free(out[0], nil, 0)

    return value
end

-- ASN.1 时间转 YYYY-MM-DD
local function get_date(time)
    if time == nil then
        return nil
    end

    local len = C.ASN1_STRING_length(time)
    local data = C.ASN1_STRING_get0_data(time)
    if data == nil or len < 10 then
        return nil
    end

    local value = ffi_string(data, len)
    local year, month, day

    if len == 11 or len == 13 then
        -- UTCTime: YYMMDDHHMMSSZ
        year = tonumber(value:sub(1, 2))
        year = year >= 50 and year + 1900 or year + 2000
        month = tonumber(value:sub(3, 4))
        day = tonumber(value:sub(5, 6))
    elseif len >= 15 then
        -- GeneralizedTime: YYYYMMDDHHMMSSZ
        year = tonumber(value:sub(1, 4))
        month = tonumber(value:sub(5, 6))
        day = tonumber(value:sub(7, 8))
    else
        return nil
    end

    return format("%04d-%02d-%02d", year, month, day)
end

-- 序列号转十进制字符串
local function get_serial(cert)
    local serial = C.X509_get_serialNumber(cert)
    if serial == nil then
        return nil
    end

    local bn = C.ASN1_INTEGER_to_BN(serial, nil)
    if bn == nil then
        return nil
    end

    local dec = C.BN_bn2dec(bn)
    local serial

    if dec ~= nil then
        serial = ffi_string(dec)
        C.CRYPTO_free(dec, nil, 0)
    end

    C.BN_free(bn)

    return serial
end

-- 解析 PEM 证书，返回证书信息
function _M.parse(pem)
    if type(pem) ~= "string" then
        return nil, "certificate is empty"
    end

    local chain, err = ngx_ssl.parse_pem_cert(pem)
    if not chain then
        return nil, err
    end

    -- ngx.ssl.parse_pem_cert 返回的是证书链，取第一张证书
    local cert = ffi.cast("X509 *", C.OPENSSL_sk_value(chain, 0))
    if cert == nil then
        return nil, "certificate chain is empty"
    end

    local issuer = C.X509_get_issuer_name(cert)

    return {
        serial = get_serial(cert),
        effectiveDate = get_date(C.X509_get0_notBefore(cert)),
        expirationDate = get_date(C.X509_get0_notAfter(cert)),
        domainName = get_name(C.X509_get_subject_name(cert), NID_CN),
        issuerName = get_name(issuer, NID_CN),
        issuerOrgName = get_name(issuer, NID_O),
    }
end

return _M
