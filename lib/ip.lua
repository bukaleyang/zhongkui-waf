local _M = {}

local bit = require "bit"
local lshift, rshift = bit.lshift, bit.rshift
local band = bit.band
local ipairs = ipairs

local base = {23, 16, 8, 0}
local maskConst = 0xffffffff

function _M.getClientIP()
    local ip = ngx.var.remote_addr
    if ip == nil then
        ip = "unknown"
    end
    ngx.ctx.ip = ip
    return ip 
end

function _M.ipToNumber(ip)
    if ip == nil or type(ip) ~= "string" then
        return 0
    end
    
    local number = 0
    local t = {}
    
    string.gsub(ip, "%d+",
        function(res)
            t[#t + 1] = res
        end
    )
    
    number = number + lshift(t[1], base[1]) * 2
    
    for i = 2, 4 do
        number = number + lshift(t[i], base[i])
    end
    
    return number
end

function _M.maskToNumber(mask)
    if mask == nil or type(mask) ~= "string" then
        return 0
    end

    local number = 0

    if string.find(mask, "%d%.") then
        number = _M.ipToNumber(mask)
    else
        if tonumber(mask) > 32 then
            return 0
        end
        number = maskConst - 2 ^ (32 - tonumber(mask)) + 1
    end
    
    return math.floor(number)
end

function _M.isSameSubnet(subnetTab, ip)
    local ipNumber = ngx.ctx.ipNumber
    if ipNumber == nil then
        ipNumber = _M.ipToNumber(ip)
        ngx.ctx.ipNumber = ipNumber
    end
    
    for value, maskNumber in pairs(subnetTab) do
        if band(ipNumber, maskNumber) == value then
            return true
        end
    end

    return false
end

-- ip黑白名单预处理，如果配置了网段，则计算网段的ip十进制数按位与掩码
function _M.initIpList(ipList)
    local result = {}
    local subnetTab = {}
    
    if #ipList == 0 then
        return result
    end
    
    for _, v in ipairs(ipList) do
        local ip = string.match(v, "([%d%.]+)/?")
        local mask = string.match(v, "/([%d%.]+)")
        
        local ipNumber = _M.ipToNumber(ip)

        if mask then
            local maskNumber = _M.maskToNumber(mask)
            local res = band(ipNumber, maskNumber)

            subnetTab[res] = maskNumber
        else
            table.insert(result, ip)
        end        
    end
    
    table.insert(result, subnetTab)

    return result
end

-- 把配置中混合在一起的单ip和ip网段区分开，{ip网段table},{ipList}
function _M.mergeAndSort(ipList1, ipList2)
    local t1, t2 = {}, {}
    
    for _, v in ipairs(ipList1) do
        if string.find(v, '/') then
            table.insert(t1, v)
        else
            table.insert(t2, v)
        end
    end
    
    for _, v in ipairs(ipList2) do
        if string.find(v, '/') then
            table.insert(t1, v)
        else
            table.insert(t2, v)
        end
    end
    
    t1 = _M.initIpList(t1)
                
    return t1, t2
end

return _M