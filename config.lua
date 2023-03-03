local _M = {}

local config = {
    -- Turn the waf on or off
    waf = "on",
    -- Specify the working mode of this waf,The following option characters are supported:
    -- monitor: Record attack logs but do not intercept attack requests
    -- protection: Intercept attack requests and record attack logs
    mode = "protection",
	
	-- 开启规则自动排序，开启后按规则命中次数降序排序，可以提高拦截效率
    rules_sort = "off",
    -- 规则每隔多少秒排序一次
    rules_sort_period = 60,
    
    -- 攻击日志
    attackLog = "on",
    -- waf日志文件路径
    logPath = "/usr/local/openresty/nginx/logs/hack/",
    -- 规则文件路径
    rulePath = "/usr/local/openresty/zhongkui-waf/rules/",
    
    -- 开启ip地理位置识别
    geoip = "on",
    -- geoip数据文件路径
    geoip_db_file = "/usr/local/share/GeoIP/GeoLite2-City.mmdb",
    -- 允许哪些国家的ip请求，其值为大写的ISO国家代码，如CN，如果设置为空值则允许所有
    geoip_allow_country = {},
    -- geoip显示语言，默认中文
    geoip_language = "zh-CN",

    -- 开启ip白名单
    whiteIP = "on",
    -- ip白名单列表，支持网段配置，"127.0.0.1/24"或"127.0.0.1/255.255.255.0"
    ipWhiteList = {"127.0.0.1"},
	
    -- 开启ip黑名单
    blackIP = "on",
    -- ip黑名单列表，支持网段配置，"127.0.0.1/24"或"127.0.0.1/255.255.255.0"，也可以配置在./rules/ipBlackList文件中
    ipBlackList = {"127.0.0.1"},
    
    -- 自动拉黑ip，拉黑日志保存在./logPath/ipBlock.log文件中
    autoIpBlock = "off",
    -- ip禁止访问时间，单位是秒，如果设置为0则永久禁止并保存在./rules/ipBlackList文件中
    ipBlockTimeout = 0,
	
    -- url白名单
    whiteURL = "on",
    -- url黑名单
    blackURL = "on",

    -- http方法白名单
    methodWhiteList = {"GET","POST","HEAD"},
    -- 请求体检查
    requestBodyCheck = "off",
    -- 上传文件类型黑名单
    fileExtBlackList = {"php","jsp","asp","exe","sh"},
    -- 上传文件内容检查
    fileContentCheck = "off",

    -- cookie检查
    cookie = "off",
    
    -- cc攻击拦截
    CCDeny = "off",
    -- 单个ip请求频率（r/s）
    CCRate = "100/60",

    -- Redis支持，打开后请求频率统计及ip黑名单将从Redis中存取
    redis = "off",
    redis_host = "",
    redis_port = "6379",
    redis_passwd = "",
    redis_ssl = false,
    redis_pool_size = "10",
    -- Respectively sets the connect, send, and read timeout thresholds (in ms)
    redis_timeouts = "1000,1000,1000",

    -- 是否重定向
    redirect = "on",
    -- 非法请求将重定向至html设置的内容
    html = [[
    <html xmlns="http://www.w3.org/1999/xhtml"><head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <title>WAF</title>
    </head>
    <h3>别闹</h3>
    </body></html>
    ]]
}


function _M.get(option)
    return config[option]
end
-- Returns true if the config option is "on",otherwise false
function _M.isOptionOn(option)
	return config[option] == "on" and true or false
end

return _M