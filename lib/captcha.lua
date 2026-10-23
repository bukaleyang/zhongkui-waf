-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2023 bukale bukale2022@163.com

local config = require "config"
local redis_cli = require "redis_cli"
local constants = require "constants"
local request = require "request"
local cjson = require "cjson"

local concat = table.concat
local sort = table.sort
local type = type

local len = string.len
local sub = string.sub
local find = string.find
local md5 = ngx.md5
local ngxsub = ngx.re.sub
local ngxgsub = ngx.re.gsub
local pairs = pairs
local tonumber = tonumber
local tostring = tostring
local upper = string.upper
local cjson_decode = cjson.decode
local cjson_encode = cjson.encode

local get_site_config = config.get_site_config
local is_system_option_on = config.is_system_option_on
local is_site_option_on = config.is_site_option_on
local get_system_config = config.get_system_config
local get_site_security_modules = config.get_site_security_modules

local CHALLENGE_HTML = get_system_config().challenge_html
local SECRET = get_system_config("secret")

local _M = {}

-- 版本标记：用于线上确认部署的 captcha.lua 版本，配合 HTML 版本注释与失败日志 ver 字段
local CAPTCHA_VERSION = "captcha.lua@1.11"

-- 启动自检：核心共享字典缺失会直接导致 500 或验证全部失败，且静默难排查
-- 字典由 nginx.conf http{} 中的 lua_shared_dict 声明（见 README.md）
if not is_system_option_on("redis") then
    -- 共享字典仅在非 redis 模式下使用；redis 开启时无需声明，避免误报
    local required_dicts = { "dict_captcha", "dict_accesstoken", "dict_blackip" }
    for _, name in ipairs(required_dicts) do
        if not ngx.shared[name] then
            ngx.log(ngx.ERR, "captcha startup check: shared dict '", name,
                "' is MISSING -> add 'lua_shared_dict ", name,
                " 10m;' to nginx.conf http{} block (see README.md)")
        end
    end
end

math.randomseed(os.time())

-- 验证请求中的AccessToken，验证通过则返回true,否则返回false
function _M.check_access_token()
    local access_token = ngx.var.cookie_waf_accesstoken

    if not access_token then
        return false
    end

    local ctx = ngx.ctx
    local ip = ctx.ip
    local ua = ctx.ua
    local host = ctx.server_name
    local key = md5(ip .. ua .. host .. SECRET)

    local token = nil
    if is_system_option_on("redis") then
        token = redis_cli.get(constants.KEY_CAPTCHA_ACCESSTOKEN_REDIS_PREFIX .. key)
    else
        local limit = ngx.shared.dict_accesstoken
        token = limit:get(key)
    end

    if token and token == access_token then
        return true
    end

    return false
end

-- 设置浏览器cookie:access_token
function _M.set_access_token()
    local ctx = ngx.ctx
    local ip = ctx.ip
    local ua = ctx.ua
    local host = ctx.server_name
    local key = md5(ip .. ua .. host .. SECRET)
    local time = ngx.time()

    local expireInSeconds = get_site_config("bot").captcha.expireInSeconds

    local access_token = upper(md5(key .. time))
    local cookie_expire = ngx.cookie_time(time + expireInSeconds)
    ngx.header['Set-Cookie'] = { 'waf_accesstoken=' .. access_token .. '; path=/; Expires=' .. cookie_expire }

    if is_system_option_on("redis") then
        redis_cli.set(constants.KEY_CAPTCHA_ACCESSTOKEN_REDIS_PREFIX .. key, access_token, expireInSeconds)
    else
        local limit = ngx.shared.dict_accesstoken
        limit:set(key, access_token, expireInSeconds)
    end
end

-- 清除浏览器cookie:access_token
function _M.clear_access_token()
    ngx.header['Set-Cookie'] = { 'waf_accesstoken=; path=/; Expires=Thu, 01-Jan-1970 00:00:00 GMT' }
end

-- 获取请求签名
function _M.get_sign(args, sign_key, secret)
    local str = ''

    if args then
        -- args 是哈希表，table.sort 对数组才有效；先收集 key 再排序，保证签名稳定
        local keys = {}
        for key in pairs(args) do
            if key ~= sign_key then
                keys[#keys + 1] = key
            end
        end
        sort(keys)

        for i = 1, #keys do
            local key = keys[i]
            local val = args[key]
            if type(val) == "table" then
                str = str .. '&' .. key .. '=' .. concat(val, ", ")
            else
                str = str .. '&' .. key .. '=' .. tostring(val)
            end
        end

        local length = len(str)
        if length > 1 then
            str = sub(str, 2)
        end
    end

    str = str .. '&secret=' .. secret

    local sign = upper(md5(str))

    return sign
end

-- 验证请求签名
function _M.sign_verify(args, sign_key, secret)
    if args then
        local req_sign = args[sign_key]
        if not req_sign then
            return false
        end

        local sign = _M.get_sign(args, sign_key, secret)

        if req_sign == sign then
            return true
        end
    end

    return false
end

-- block ip
local function block_ip(ip, rule_table)
    if upper(rule_table.autoIpBlock) == "ON" and ip then
        local ok, err = nil, nil

        if is_system_option_on("redis") then
            local key = constants.KEY_BLACKIP_PREFIX .. ip

            ok, err = redis_cli.set(key, 1, rule_table.ipBlockExpireInSeconds)
            if ok then
                ngx.ctx.ip_blocked = true
            else
                ngx.log(ngx.ERR, "failed to block ip " .. ip, err)
            end
        else
            local blackip = ngx.shared.dict_blackip
            ok, err = blackip:set(ip, 1, rule_table.ipBlockExpireInSeconds)
            if ok then
                ngx.ctx.ip_blocked = true
            else
                ngx.log(ngx.ERR, "failed to block ip " .. ip, err)
            end
        end

        return ok
    end
end

-- 429 拒：超过最大失败次数后的冷却期内不再出题
local function too_many_requests()
    ngx.status = 429
    ngx.header.content_type = "application/json"
    ngx.print(cjson_encode({ result = "fail", reason = "尝试次数过多，请稍后重试" }))
    return ngx.exit(429)
end

-- 存储封装（redis / shared dict 两套后端统一接口）
local function store_get(key)
    if is_system_option_on("redis") then
        return redis_cli.get(key)
    end
    return ngx.shared.dict_captcha:get(key)
end

local function store_set(key, value, exptime)
    if is_system_option_on("redis") then
        return redis_cli.set(key, value, exptime)
    end
    return ngx.shared.dict_captcha:set(key, value, exptime)
end

local function store_del(key)
    if is_system_option_on("redis") then
        redis_cli.bath_del({ key })
        return
    end
    ngx.shared.dict_captcha:delete(key)
end

local function store_incr(key, exptime)
    if is_system_option_on("redis") then
        return redis_cli.incr(key, exptime)
    end
    return ngx.shared.dict_captcha:incr(key, 1, 0, exptime)
end

-- 日志节流：同一 throttle_key 每秒只放行一次，返回 true 才允许输出完整诊断日志。
-- 失败/通过日志都带完整遥测+UA，高 QPS 会刷爆 error.log，故统一走此节流。
local function throttle_allow(throttle_key)
    if store_get(throttle_key) then
        return false
    end
    store_set(throttle_key, 1, 1)
    return true
end

-- 原子占位（SETNX / ADD）：仅当 key 不存在时写入并返回 true，否则返回 false。
-- 用于一次性 nonce 消费的互斥，消除"先 get 后 delete"跨 worker 的窄窗口竞态。
local function store_add(key, exptime)
    if is_system_option_on("redis") then
        return redis_cli.add(key, 1, exptime) == true
    end
    local ok = ngx.shared.dict_captcha:add(key, 1, exptime)
    return ok == true
end

-- 评分阈值默认值（可被 config 中的配置覆盖）
-- 总分 = formula_score(0~60) + browser_score(0~30) + behavior_bonus(0~10) = 满分 100
-- 多因子综合判定：公式正确（必要但不充分）+ 浏览器环境 + 行为信号，缺一不可
local SCORE_THRESHOLD_PASS = 70      -- >= 70 直接放行
local SCORE_THRESHOLD_CHALLENGE = 50 -- >= 50 轻度挑战（重新验证）

-- 通过日志全局节流：每秒最多输出 MAX_CAPTCHA_SUCCESS_LOGS_PER_SEC 条完整通过日志。
-- 失败日志已按 IP 每秒节流；但通过者是代理池农场（每 IP 只发一两次），单 IP 节流挡不住，
-- 必须叠加全局计数（store_incr 1s 窗口）防止刷爆 error.log。
local MAX_CAPTCHA_SUCCESS_LOGS_PER_SEC = 20

-- 单个 IP 在验证窗口内最多可下发挑战页的次数（按 IP 统计，不随 UA 轮换而重置）。
-- 防止攻击者通过持续刷新挑战页刷满 nonce/formula 存储（共享字典或 Redis），造成全站验证失效（DoS）。
-- 阈值需兼顾 NAT 后的多人共享出口 IP；挑战页内联样式/脚本、无外部子资源，正常流程每次窗口仅数次。
local MAX_CHALLENGE_SERVES_PER_WINDOW = 200

-- 读取验证窗口并钳制下限（默认 300s，最小 30s）。
-- 防止误配为 0/过小导致整站验证窗口失效，并保证各处存储 TTL 与窗口判断一致。
local function get_verify_window(captcha)
    local window = tonumber(captcha.verifyInSeconds) or 300
    if window < 30 then
        ngx.log(ngx.ERR, "captcha verifyInSeconds=", tostring(captcha.verifyInSeconds),
            " too small, clamped to 30s (check admin bot config)")
        window = 30
    end
    return window
end

-- 计算公式得分（正确性 40 分 + 耗时 20 分，满分 60，必要但不充分）
-- 耗时由服务端独立测量（challenge 生成时间 → 验证提交时间），不信任客户端提交的 elapsed
-- 正常流程含固定 3 秒等待，故完整耗时约 3000ms 起；耗时越短越可疑：
--   elapsed < 500ms：视为脚本即时提交，直接否决（第二返回值 too_fast=true）
--   elapsed < 2000ms：快速提交，扣 15 分（干净浏览器也无法直达 success）
--   其余按 0~20 比例给耗时分
local function calc_formula_score(elapsed, is_correct)
    if not is_correct then
        return 0, false, "wrong_result"
    end
    local e = tonumber(elapsed)
    if e and e >= 0 and e < 500 then
        return 0, true, "too_fast"
    end
    local correctness = 40
    local time_score = 0
    if e then
        if e >= 3000 then
            time_score = 20
        elseif e > 0 and e < 3000 then
            time_score = math.floor(20 * e / 3000)
        end
    end
    local score = correctness + time_score
    local reason = "ok"
    if e and e >= 0 and e < 2000 then
        score = score - 15
        reason = "fast_submit"
    end
    return math.max(0, score), false, reason
end

-- 一次性校验并消费 challenge_id（nonce）
-- 返回：challenge_id 匹配时返回 (true, challenge_ts)，否则返回 (false, nil)
-- 注意：无论匹配与否，该 nonce 都会被作废，防止 replay 攻击
-- key 仅由提交的 challenge_id 决定：并发/重试 serve 互不覆盖，验证不依赖请求上下文（ip/ua/host）
local function consume_challenge(submit_challenge_id)
    if not submit_challenge_id then
        return false, nil
    end

    local challenge_key = constants.KEY_CAPTCHA_PREFIX .. "nonce:" .. submit_challenge_id

    -- 原子互斥：同一 nonce 只能被一个请求消费。
    -- 用 claim 键做 SETNX/ADD，先抢到者才有权 get+delete，彻底消除跨 worker 的窄窗口重复消费。
    -- claim 在消费完成后立即删除（此时 nonce 已删，重复请求因 nonce 缺失而失败），不残留占位。
    local claim_key = challenge_key .. ":claim"
    if not store_add(claim_key, 60) then
        return false, nil -- 已被其他并发请求消费
    end

    local stored_val = nil
    if is_system_option_on("redis") then
        stored_val = redis_cli.get(challenge_key)
        redis_cli.bath_del({ challenge_key, claim_key }) -- 一次性：无论成败都作废
    else
        local limit = ngx.shared.dict_captcha
        stored_val = limit:get(challenge_key)
        limit:delete(challenge_key) -- 一次性：无论成败都作废
        limit:delete(claim_key)
    end

    if not stored_val then
        return false, nil
    end

    -- stored_val 格式：challenge_id_<unix_ms>
    local index = find(stored_val, "_", 1, true)
    if not index then
        return false, nil
    end
    local stored_id = sub(stored_val, 1, index - 1)
    local challenge_ts = tonumber(sub(stored_val, index + 1))

    if stored_id == submit_challenge_id then
        return true, challenge_ts
    end
    return false, challenge_ts
end

-- 服务端独立计算浏览器环境得分（不信任客户端提交的分值）
-- 满分 30 分扣分制；返回 -1 为一票否决，0~30 参与总分累加
-- 原始字段优先判定，缺失时用 browser_info.details 剩余分兜底，缺失返回 nil
local function details_ok(det, key, full_score)
    local remain = tonumber(det[key])
    if remain == nil then
        return nil
    end
    return remain >= full_score
end

local function calc_browser_score(browser_info)
    if not browser_info or type(browser_info) ~= "table" then
        return -1, "no_info"
    end

    -- 几乎不带任何原始遥测字段的 browser_info 视为不可信。
    -- 真实浏览器必然携带 userAgent/cookieEnabled/screenWidth 等核心字段；
    -- 空对象（或只塞一两个字段的伪装）不满足最低信息量 → 一票否决
    local telemetry_keys = {
        "userAgent", "cookieEnabled", "screenWidth", "screenHeight",
        "availWidth", "availHeight", "nativeFailedCount", "webglRenderer",
        "plugins", "mimeTypes", "language", "languages", "hasTouch", "headlessGlobals",
        "platform", "maxTouchPoints", "devicePixelRatio", "innerWidth", "innerHeight",
    }
    local present = 0
    for i = 1, #telemetry_keys do
        if browser_info[telemetry_keys[i]] ~= nil then
            present = present + 1
        end
    end
    if present < 2 then
        return -1, "no_telemetry"
    end

    local score = 30
    local reasons = {}
    local add_reason = function(r) reasons[#reasons + 1] = r end
    local info = browser_info
    local det = (type(info.details) == "table") and info.details or {}

    local ua = tostring(info.userAgent or ""):lower()
    local banned = { 'headless', 'webdriver', 'puppeteer', 'selenium', 'chromedriver', 'phantomjs' }
    for i = 1, #banned do
        if find(ua, banned[i], 1, true) then
            return -1, "banned_ua:" .. banned[i]
        end
    end

    local mobile_keywords = { 'android', 'webos', 'iphone', 'ipad', 'ipod', 'blackberry', 'windows phone', 'mobile' }
    local is_mobile = false
    for i = 1, #mobile_keywords do
        if find(ua, mobile_keywords[i], 1, true) then
            is_mobile = true
            break
        end
    end

    -- 一票否决：headless 全局变量或 webdriver 标记
    local hlg = info.headlessGlobals
    if hlg and hlg ~= "" and (type(hlg) ~= "table" or #hlg > 0) then
        return -1, "headless_global"
    end
    local wd = tostring(info.webdriver):lower()
    if wd == "true" or wd == "1" then
        return -1, "webdriver"
    end

    local cookie = tostring(info.cookieEnabled):lower()
    if cookie == "false" or cookie == "nil" then
        score = score - 4
        add_reason("cookie")
    end

    local renderer = tostring(info.webglRenderer or ""):lower()
    local soft = tostring(info.webglSoftware):lower()
    -- 软件渲染（SwiftShader/llvmpipe/webglSoftware=true）见于无 GPU 环境（headless/云浏览器），
    -- 以及真实老机器（关闭硬件加速/无独显驱动/RDP/VM）。真实机器无独显且硬件加速开启时
    -- 走 ANGLE D3D11（含 Basic Render Driver）。verify 层据此对移动端模拟器硬否决、桌面端平台一致放行。
    local software_renderer = (soft == "true")
        or (find(renderer, "swiftshader") ~= nil)
        or (find(renderer, "llvmpipe") ~= nil)
    local webgl_bad = software_renderer
        or renderer == "unsupported"
        or (renderer == "" and details_ok(det, "webgl", 10) == false)
    if webgl_bad then
        score = score - 5
        add_reason("webgl")
    end

    -- 桌面端插件缺失判定（-3）
    if not is_mobile then
        local plugins = tonumber(info.plugins)
        local mime = tonumber(info.mimeTypes)
        if not ((plugins and plugins > 0) or (mime and mime > 0)) then
            local plugin_ok = details_ok(det, "plugins", 10)
            if plugin_ok == nil then
                plugin_ok = not (plugins ~= nil and plugins <= 0)
            end
            if not plugin_ok then
                score = score - 3
                add_reason("plugins")
            end
        end
    end

    local sw = tonumber(info.availWidth) or tonumber(info.screenWidth) or 0
    local sh = tonumber(info.availHeight) or tonumber(info.screenHeight) or 0
    local min_w = is_mobile and 200 or 400
    local min_h = is_mobile and 300 or 400
    if sw < min_w or sh < min_h then
        score = score - 3
        add_reason("screen")
    end

    local langs = tostring(info.languages or "")
    if tostring(info.language or "") == "" or langs == "" or langs == "undefined" then
        score = score - 3
        add_reason("language")
    end

    -- 原生函数被覆盖检测（Selenium/Puppeteer 会 patch eval、document.querySelector 等）
    -- 仅用原始字段独立判定；字段缺失时退回前端 details 剩余分
    local native_failed = tonumber(info.nativeFailedCount)
    if native_failed then
        if native_failed > 0 then
            score = score - math.min(6, math.floor(native_failed * 2))
            add_reason("native")
        end
    elseif details_ok(det, "nativeFunctions", 10) == false then
        score = score - 4
        add_reason("native")
    end

    -- 交叉一致性检查（原始遥测字段独立判定，不信任前端评分）
    -- UA 与 platform 必须同族（Win/Mac/Linux/Android 四组）
    -- 注：iPhone/iPad/iPod 的 UA 含 "like Mac OS X"，iOS12 以下 platform 为
    -- "iPhone/iPad/iPod"，需放行；iOS13+ 一律为 "MacIntel"
    -- 农场特征升级：真实 Linux 桌面 UA 必含 "Linux"、Android 真机必含 "Android"，
    -- 故 UA 为 Win/Mac 而 platform 却是 Linux 族（x86_64/arm 等）只出现在代理农场/
    -- 反指纹伪装（生产日志 17.4 万条全命中、真实用户 0 命中）。命中后在验证链降级为
    -- challenge（不可计次、自动重试），即使农场后续补上环境信标也过不去。
    local plat = tostring(info.platform or ""):lower()
    local ua_win = find(ua, "windows", 1, true)
    local ua_mac = find(ua, "mac os x", 1, true)
    local ua_android = find(ua, "android", 1, true)
    local ua_apple_mob = find(ua, "iphone", 1, true) or find(ua, "ipad", 1, true) or find(ua, "ipod", 1, true)
    local platform_spoof = false
    if info.platform ~= nil then
        local plat_ok = true
        if ua_win and not find(plat, "win", 1, true) then
            plat_ok = false
        elseif ua_mac and not find(plat, "mac", 1, true)
            and not (ua_apple_mob and (find(plat, "iphone", 1, true) or find(plat, "ipad", 1, true) or find(plat, "ipod", 1, true))) then
            plat_ok = false
        elseif ua_android and not find(plat, "linux", 1, true) and not find(plat, "android", 1, true) then
            plat_ok = false
        end
        if not plat_ok then
            score = score - 4
            add_reason("platform")
            if find(plat, "linux", 1, true) or find(plat, "x11", 1, true) then
                platform_spoof = true
            end
        end
    end

    -- 移动端 UA 必须支持触控（真实手机 maxTouchPoints > 0）
    local mtp = tonumber(info.maxTouchPoints)
    if mtp ~= nil and is_mobile and mtp == 0 then
        score = score - 3
        add_reason("no_touch_points")
    end

    -- devicePixelRatio 恒为正，0/负值只出现在伪造环境
    local dpr = tonumber(info.devicePixelRatio)
    if dpr ~= nil and dpr <= 0 then
        score = score - 2
        add_reason("dpr")
    end

    -- 桌面端窗口过小可疑（headless 常用小视口）
    local iw = tonumber(info.innerWidth) or 0
    if iw > 0 and not is_mobile and iw < 200 then
        score = score - 2
        add_reason("small_window")
    end

    -- 新遥测字段全部缺失时，退回前端 consistency 详情判定
    if info.platform == nil and info.maxTouchPoints == nil
        and info.devicePixelRatio == nil and info.innerWidth == nil then
        if details_ok(det, "consistency", 10) == false then
            score = score - 3
            add_reason("consistency")
        end
    end

    if is_mobile then
        local touch_ok = tostring(info.hasTouch):lower() == "true"
            or details_ok(det, "touchSupport", 5) == true
        if not touch_ok then
            score = score - 2
            add_reason("no_touch")
        end
    end

    return math.max(0, math.min(30, score)), reasons, software_renderer, platform_spoof, is_mobile
end

-- 服务端独立计算行为信号加分（不信任客户端提交的值）
-- 仅根据信号的"存在性"做基础加分，上限 10 分
local function calc_behavior_bonus(behavior)
    if not behavior then
        return 0
    end
    local bonus = 0
    local mouseMoves = tonumber(behavior.mouseMoves) or 0
    local scrollEvents = tonumber(behavior.scrollEvents) or 0
    local keyEvents = tonumber(behavior.keyEvents) or 0
    if mouseMoves > 0 then
        bonus = bonus + 4
    end
    if scrollEvents > 0 then
        bonus = bonus + 3
    end
    if keyEvents > 0 then
        bonus = bonus + 3
    end
    return math.min(bonus, 10)
end

local function get_random_formula()
    -- 运算符权重：+、- 各 3 份，* 2 份，（让加减出现概率更高，更自然）
    local operators = { '+', '+', '+', '-', '-', '-', '*', '*' }
    local op_count = #operators

    -- 随机 3~5 次迭代
    local iterations = math.random(3, 5)

    -- 为每次迭代预生成操作数和运算符
    local nums = {}
    local ops = {}
    for i = 1, iterations do
        local op = operators[math.random(op_count)]
        ops[i] = op
        if op == '*' then
            nums[i] = math.random(2, 9)  -- 乘法因子不宜过大
        else
            nums[i] = math.random(1, 99) -- 加减法操作数范围大
        end
    end

    -- 初始操作数
    local first_num = math.random(1, 99)
    local formula = tostring(first_num)
    local result

    -- 构建表达式字符串（Lua 与 JS 的四则运算语法一致）
    for i = 1, iterations do
        local op = ops[i]
        local num = nums[i]

        -- 随机决定是否给当前已积累的表达式加括号（50% 概率，最后一步不加）
        local wrap_paren = (i < iterations) and (math.random(2) == 1)

        if wrap_paren then
            formula = '(' .. formula .. op .. tostring(num) .. ')'
        else
            formula = formula .. op .. tostring(num)
        end
    end

    -- 用 Lua 按表达式字符串求值，确保结果与 JS eval 完全一致
    -- LuaJIT 兼容 Lua 5.1，使用 loadstring 而非 load
    local ok, f = pcall(loadstring, "return " .. formula)
    if not ok or type(f) ~= "function" then
        ngx.log(ngx.ERR, "captcha formula loadstring failed: " .. tostring(formula))
        -- 降级：返回简单公式
        formula = tostring(math.random(1, 99)) .. "+" .. tostring(math.random(1, 99))
        ok, f = pcall(loadstring, "return " .. formula)
        if not ok or type(f) ~= "function" then
            formula, result = "1+1", 2
        else
            result = f()
        end
    else
        result = f()
    end

    return formula, result
end

-- 汇总扣分原因（浏览器扣分项 + 公式耗时项），供排障日志使用
local function summarize_reasons(browser_reasons, formula_reason)
    local parts = {}
    if formula_reason and formula_reason ~= "ok" then
        parts[#parts + 1] = "formula:" .. formula_reason
    end
    if type(browser_reasons) == "table" then
        for i = 1, #browser_reasons do
            parts[#parts + 1] = "browser:" .. tostring(browser_reasons[i])
        end
    end
    if #parts == 0 then
        return "none"
    end
    return concat(parts, ",")
end

-- 汇总浏览器原始遥测关键字段，供排障日志定位误杀原因
local function summarize_browser_info(info)
    if type(info) ~= "table" then
        return "none"
    end
    return "ua=" .. tostring(info.userAgent or "-")
        .. " plat=" .. tostring(info.platform or "-")
        .. " mtp=" .. tostring(info.maxTouchPoints or "-")
        .. " dpr=" .. tostring(info.devicePixelRatio or "-")
        .. " iw=" .. tostring(info.innerWidth or "-")
        .. " nf=" .. tostring(info.nativeFailedCount or "-")
        .. " webgl=" .. tostring(info.webglRenderer or "-") .. "/" .. tostring(info.webglSoftware or "-")
        .. " cookie=" .. tostring(info.cookieEnabled or "-")
        .. " plugins=" .. tostring(info.plugins or "-")
        .. " touch=" .. tostring(info.hasTouch or "-")
        .. " screen=" .. tostring(info.screenWidth or "-") .. "x" .. tostring(info.screenHeight or "-")
        .. " lang=" .. tostring(info.language or "-")
end

-- 挑战会话 cookie 派生：纯函数，(challenge_id, probe_token) 逐字符移位混叠为 64 位 hex。
-- 与挑战页 JS（challenge.html 内同名逻辑）必须保持一致（注意 Lua 1 索引 vs JS 0 索引的换算）。
-- 关键点：该值不在页面中以明文出现，必须执行页面 JS 计算才能得到——纯 HTTP 脚本
-- （只做文本正则提取、不执行 JS，也不读 Set-Cookie）无法构造，天然挡掉当前农场管线。
local function waf_challenge_value(challenge_id, probe_token)
    local s = upper(challenge_id .. tostring(probe_token or ""))
    local out = {}
    for i = 1, #s do
        local d = tonumber(sub(s, i, i), 16)
        local k = ((i - 1) * 5 + 1) % 16
        out[i] = string.format("%X", (d + k) % 16)
    end
    return table.concat(out)
end

local function js_challenge()
    local args = {}
    local time = ngx.time()

    local req_sign = ngx.var.http_captcha_sign
    local req_time = tonumber(ngx.var.http_captcha_time)

    local captcha = get_site_config("bot").captcha

    -- verifyInSeconds 钳制下限（默认 300s）：防止误配为 0/过小导致整站验证窗口失效
    -- 同时用于 nonce/formula 的存储 TTL，避免"窗口判断通过但 nonce 已过期"的矛盾
    local verify_window = get_verify_window(captcha)

    -- 从配置中读取评分阈值，未配置则使用默认值
    -- 钳制下限，防止误配为 0 导致挑战完全失效；并约束 pass >= challenge 的关系
    local raw_pass = tonumber(captcha.scoreThresholdPass)
    local raw_challenge = tonumber(captcha.scoreThresholdChallenge)
    local score_threshold_pass = raw_pass and math.max(60, raw_pass) or SCORE_THRESHOLD_PASS
    local score_threshold_challenge = raw_challenge and math.max(30, raw_challenge) or SCORE_THRESHOLD_CHALLENGE
    if score_threshold_challenge > score_threshold_pass then
        score_threshold_challenge = score_threshold_pass
    end

    local ctx = ngx.ctx
    local ip = ctx.ip
    local ua = ctx.ua
    local host = ctx.server_name
    local key_captcha = constants.KEY_CAPTCHA_PREFIX .. md5(ip .. ua .. host .. SECRET)
    local key_cooldown = key_captcha .. ":cooldown"
    -- 失败次数阈值由配置决定；冷却时长固定 60 秒
    local max_fail = tonumber(captcha.maxFailTimes) or 3
    local cooldown_seconds = 60
    local rule_table = ngx.ctx.rule_table

    -- 排障字段：验证分支内填充，供失败/通过诊断日志输出（含得分分解与扣分原因、服务端计时）
    local detail_formula = nil
    local detail_browser = nil
    local detail_behavior = nil
    local detail_reasons = nil
    local detail_info = nil
    local detail_elapsed = nil

    local uri = ngx.var.uri
    if uri == '/captcha/challenge' then
        local challenge_result = { result = 'fail' }

        -- 该次失败是否计入升级计数（maxFailTimes）：在评分判定时置位，供下方失败计数块读取。
        -- 提升到验证分支顶层作用域：评分判定深嵌套，而计数块在较浅作用域，若在判定块内
        -- local 声明则计数块读到的是 nil（不可见），会导致永远不计数（线上曾踩此坑）。
        local countable_fail = false

        -- 排障字段：协议层失败（签名/时间窗）时记录具体原因
        local detail_protocol = nil
        -- 环境信标失败细分（beacon_missing / beacon_ip_mismatch / token_missing / cookie_mismatch），
        -- 排障时区分"拦截扩展拦截信标"与"农场拆分多 IP 分工"等不同根因
        local detail_probe = nil
        -- 原始行为计数（m/s/k），确认是否为零交互自动提交
        local detail_signals = nil
        -- payload 解析状态：区分"未携带 payload 字段"与"payload JSON 解析失败"
        local detail_payload_field = false
        local detail_payload_ok = false

        -- payload 提升到分支级作用域：失败日志按 challenge_id 定位必须能读到解析结果
        local payload = nil
        -- 签名是否通过：用于区分"签名错误"与"签名通过但 payload 缺失/解析失败"
        local sign_pass = false

        if req_sign and req_time and ((req_time + verify_window) >= time) then
            args["Captcha-Sign"] = req_sign
            args["Captcha-Time"] = req_time
            local pass = _M.sign_verify(args, "Captcha-Sign", SECRET)
            if pass then
                sign_pass = true
                args = request.get_post_args()
                if args then
                    -- 尝试解析 JSON payload
                    local payload_str = args['payload']
                    payload = nil
                    local payload_field = payload_str ~= nil
                    if payload_str then
                        local ok, decoded = pcall(cjson_decode, payload_str)
                        if ok then
                            payload = decoded
                        end
                    end
                    detail_payload_field = payload_field
                    detail_payload_ok = payload ~= nil

                    if payload then
                        -- 消费一次性 challenge_id（nonce）：无论校验成功与否都作废，杜绝 replay 攻击
                        -- 服务端返回的 challenge_ts 用于独立测量计算耗时，不信任客户端提交的 elapsed
                        -- nonce 单独存储，key 仅由提交的 challenge_id 决定，与请求上下文无关
                        local challenge_ok, challenge_ts = consume_challenge(payload.challenge_id)

                        if not challenge_ok then
                            ngx.log(ngx.ERR, "captcha consume failed: submit_id=", tostring(payload.challenge_id),
                                " key=", constants.KEY_CAPTCHA_PREFIX, "nonce:", tostring(payload.challenge_id),
                                " redis=", tostring(is_system_option_on("redis")))
                            -- challenge_id 缺失、不匹配或已被消费，直接拒绝
                            challenge_result = {
                                result = 'fail',
                                reason = '验证请求无效或已过期，请重新验证'
                            }
                        else
                            local res = payload.captcha_result
                            if not res then
                                challenge_result = { result = 'fail', reason = '缺少计算结果' }
                            else
                                -- 从缓存获取正确结果（公式与 nonce 绑定存储，key 仅由 challenge_id 决定）
                                local formula_key = constants.KEY_CAPTCHA_PREFIX ..
                                    "nonce:" .. payload.challenge_id .. "/f"
                                local stored_result = nil

                                if is_system_option_on("redis") then
                                    stored_result = redis_cli.get(formula_key)
                                    if stored_result then
                                        local index = find(stored_result, "_", 1, true)
                                        stored_result = index and sub(stored_result, index + 1) or nil
                                    end
                                    redis_cli.bath_del({ formula_key }) -- 一次性：作废对应公式
                                else
                                    local limit = ngx.shared.dict_captcha
                                    stored_result = limit:get(formula_key)
                                    if stored_result then
                                        local index = find(stored_result, "_", 1, true)
                                        stored_result = index and sub(stored_result, index + 1) or nil
                                    end
                                    limit:delete(formula_key) -- 一次性：作废对应公式
                                end

                                if stored_result then
                                    -- 验证公式结果是否正确
                                    local num_res = tonumber(res)
                                    local num_stored = tonumber(stored_result)
                                    local is_correct = (num_res ~= nil and num_stored ~= nil and num_res == num_stored)

                                    -- 服务端独立测量计算耗时（毫秒），不信任客户端提交的 elapsed
                                    local elapsed = math.floor(ngx.now() * 1000) - (challenge_ts or 0)
                                    detail_elapsed = elapsed

                                    local formula_score, formula_too_fast, formula_reason = calc_formula_score(elapsed,
                                        is_correct)
                                    local browser_score, browser_reasons, software_renderer, platform_spoof, is_mobile =
                                        calc_browser_score(payload.browser_info)
                                    -- 老 Windows 真机（关闭硬件加速/无 GPU 驱动/RDP/VM -> SwiftShader）桌面端且平台与 UA
                                    -- 同族时放行走评分（不进入软件渲染硬否决分支，否则 elseif 链会跳过下方评分）。
                                    -- 移动端 SwiftShader（Android/iOS 模拟器）与 platform 伪装（农场）保持硬否决。
                                    local legacy_software_pass = (not is_mobile) and (not platform_spoof)
                                    local behavior_bonus = calc_behavior_bonus(payload.behavior)
                                    local _be = type(payload.behavior) == "table" and payload.behavior or {}
                                    detail_signals = "m=" .. tostring(_be.mouseMoves or 0)
                                        .. " s=" .. tostring(_be.scrollEvents or 0)
                                        .. " k=" .. tostring(_be.keyEvents or 0)

                                    detail_formula = formula_score
                                    detail_browser = browser_score
                                    detail_behavior = behavior_bonus
                                    detail_reasons = summarize_reasons(browser_reasons, formula_reason)
                                    detail_info = summarize_browser_info(payload.browser_info)

                                    -- 综合评分
                                    local total_score = formula_score + browser_score + behavior_bonus

                                    -- 环境信标（隐藏 1x1 图）必须已被页面真实加载，且信标请求 IP 必须与验证
                                    -- POST 同源；挑战 cookie 必须是由挑战页 JS 基于 (challenge_id, probe_token)
                                    -- 计算出的值（纯 HTTP 脚本不执行 JS 构造不出该 cookie；固定值/读 Set-Cookie 均失效）。
                                    -- 三者任一不过即判定为 challenge（自动重试，不计升级）。
                                    -- 信标与 probe_token 均一次性：验证后即作废，防止复用。
                                    local probe_pass = true
                                    -- cookie_mismatch / beacon_ip_mismatch 单独标记（不硬否决）：见下方判定。
                                    local cookie_mismatch = false
                                    local beacon_ip_mismatch = false
                                    if captcha.environmentProbe ~= false then
                                        local cid = tostring(payload.challenge_id)
                                        local beacon_key = constants.KEY_CAPTCHA_PREFIX .. "beacon:" .. cid
                                        local beacon_ip = store_get(beacon_key)
                                        store_del(beacon_key)
                                        if beacon_ip == nil then
                                            probe_pass = false
                                            detail_probe = "beacon_missing"
                                        elseif tostring(beacon_ip) ~= tostring(ip or ngx.ctx.ip or ngx.var.remote_addr) then
                                            -- beacon_ip_mismatch：信标 IP ≠ 验证 IP。常见于移动端 WiFi→4G 切换、
                                            -- 多出口 NAT、CDN 回源等场景——信标加载与验证 POST 走不同出口 IP。
                                            -- 与 cookie_mismatch 类似，标记后走下方扣分降级（score≥80 + 无农场特征 → 放行），
                                            -- 而非硬否决，避免误杀高分真实移动用户。
                                            beacon_ip_mismatch = true
                                            detail_probe = "beacon_ip_mismatch"
                                        else
                                            local probe_key = constants.KEY_CAPTCHA_PREFIX .. "nonce:" .. cid .. "/p"
                                            local probe_token = store_get(probe_key)
                                            store_del(probe_key)
                                            if probe_token == nil then
                                                probe_pass = false
                                                detail_probe = "token_missing"
                                            elseif ngx.var.cookie_waf_challenge ~= waf_challenge_value(cid, probe_token) then
                                                -- cookie 与预期不符。注意：能走到此分支，说明 beacon 信标已回传且
                                                -- IP 一致、probe_token 有效——即挑战页确实被真实渲染并执行了 JS
                                                -- （纯 HTTP 脚本/无头工具在 beacon 阶段即被拦截）。此时 cookie 不匹配
                                                -- 多为老浏览器/壳浏览器/WebView 或隐私模式的 cookie 写入失败，
                                                -- 若硬否决会误杀高分真实用户（生产实证 9 条 score 87-91 样本）。
                                                -- 故不置 probe_pass=false，仅标记后走下方扣分降级。
                                                cookie_mismatch = true
                                                detail_probe = "cookie_mismatch"
                                            end
                                        end
                                    end

                                    -- 判定优先级：探测失败 -> 秒交(<500ms) -> 软件渲染 -> platform 伪装 -> headless 工具链 -> 评分
                                    -- 软件渲染（SwiftShader/llvmpipe/webglSoftware=true）只见于无 GPU 环境：headless/云浏览器，
                                    -- 以及真实老机器（关闭硬件加速 / 无独显驱动 / RDP / 虚拟机）。真实机器无独显且硬件加速
                                    -- 开启时走 ANGLE D3D11（含 Basic Render Driver），不在软件渲染之列。
                                    -- 软件渲染硬否决仅保留给"移动端模拟器/可疑形态"；桌面端且 platform 与 UA 同族的
                                    -- SwiftShader 放行走评分（老 Windows 真机 85~89 分直接通过），避免误判拦截此类用户。
                                    -- 农场（Win/Mac UA + Linux 系 platform，v1.8 期间 17.4 万条 100% 命中）仍被下方
                                    -- platform_spoof 分支拦截，与软件渲染是否放行无关。
                                    -- captcha.softwareWebglVeto=false 可整体关闭软件渲染否决。
                                    -- 可计入升级计数（maxFailTimes）的仅限明确机器人信号（秒交/工具链/低分）；
                                    -- 探测失败、移动端模拟器、platform 伪装与 challenge 均降级为 challenge（页面自动重试、不计升级），
                                    -- 避免误锁禁用硬件加速 / 开拦截扩展 / 反指纹随机化的真实用户（农场仍会被无限 challenge 挡住）。
                                    -- cookie_mismatch 降级：仅扣分不走否决，高分真实用户（87-91 -> 72-76）仍 >=70 通过；
                                    -- 农场即便伪造 cookie 也无意义（其 score 本就低于通过线）。扣分保持对异常环境的轻微惩罚。
                                    if cookie_mismatch then
                                        total_score = total_score - 15
                                    end
                                    -- beacon_ip_mismatch 降级：移动端 WiFi→4G 切换、多出口 NAT 导致信标 IP ≠ 验证 IP。
                                    -- 策略：score≥80 + 无农场特征（platform_spoof/beacon_missing/headless）→ 扣 10 分放行；
                                    -- 农场 score 本就 <70，扣分后更不会误放；score<80 的 beacon_ip_mismatch 保留硬否决
                                    -- （低分 + IP 不一致 = 更高可疑度）。
                                    if beacon_ip_mismatch then
                                        local has_farm_signal = platform_spoof
                                            or (not probe_pass) -- beacon_missing 等已硬否决
                                            or (ua or ''):find('HeadlessChrome', 1, true)
                                        if not has_farm_signal and total_score >= 80 then
                                            total_score = total_score - 10
                                        else
                                            probe_pass = false
                                        end
                                    end
                                    if not probe_pass then
                                        challenge_result = {
                                            result = 'challenge',
                                            score = total_score,
                                            reason = '浏览器环境检测未通过，请重试验证'
                                        }
                                    elseif formula_too_fast then
                                        countable_fail = true
                                        challenge_result = {
                                            result = 'fail',
                                            score = total_score,
                                            reason = '提交过于迅速，疑似自动化工具'
                                        }
                                    elseif captcha.softwareWebglVeto ~= false and software_renderer and not legacy_software_pass then
                                        challenge_result = {
                                            result = 'challenge',
                                            score = total_score,
                                            reason = '浏览器环境异常，请重试验证'
                                        }
                                    elseif platform_spoof then
                                        challenge_result = {
                                            result = 'challenge',
                                            score = total_score,
                                            reason = '浏览器环境异常，请重试验证'
                                        }
                                    elseif browser_score == -1 then
                                        countable_fail = true
                                        challenge_result = {
                                            result = 'fail',
                                            score = total_score,
                                            reason = '浏览器环境异常，疑似自动化工具'
                                        }
                                    elseif total_score >= score_threshold_pass then
                                        challenge_result = { result = 'success', score = total_score }

                                        if is_system_option_on("redis") then
                                            redis_cli.bath_del({ key_captcha, key_cooldown, constants.KEY_CAPTCHA_PREFIX ..
                                            "serve:" .. tostring(ip) })
                                        else
                                            local limit = ngx.shared.dict_captcha
                                            limit:delete(key_captcha)
                                            limit:delete(key_cooldown)
                                            limit:delete(constants.KEY_CAPTCHA_PREFIX .. "serve:" .. tostring(ip))
                                        end

                                        _M.set_access_token()
                                        ngx.ctx.is_captcha_pass = true
                                    elseif total_score >= score_threshold_challenge then
                                        -- 轻度挑战：公式正确但环境可疑，提示重新验证
                                        challenge_result = {
                                            result = 'challenge',
                                            score = total_score,
                                            reason = '需要额外验证，请重试'
                                        }
                                    else
                                        -- 拒绝
                                        countable_fail = true
                                        challenge_result = {
                                            result = 'fail',
                                            score = total_score,
                                            reason = '浏览器环境评分过低'
                                        }
                                    end
                                else
                                    -- 公式缓存已过期（与 challenge nonce TTL 不同步），返回明确失败原因
                                    challenge_result = {
                                        result = 'fail',
                                        reason = '验证已过期，请刷新页面重新验证'
                                    }
                                end
                            end
                            -- 失败计数/升级：仅在"消耗了有效 nonce 且判定为可计数的硬失败"时 +1
                            -- 页面/子资源请求、签名/时间/nonce 协议失败、challenge 结果、probe 失败、验证过期一律不计
                            if challenge_ok and countable_fail then
                                local fails = store_incr(key_captcha, verify_window) or 0
                                if tonumber(fails) >= max_fail then
                                    -- 超过最大失败次数：进入冷却期（冷却期内后续请求返回 429）；是否拉黑 IP 由规则表 autoIpBlock 控制（默认 OFF 不封禁）
                                    store_set(key_cooldown, 1, cooldown_seconds)
                                    store_del(key_captcha)
                                    if rule_table and ip then
                                        block_ip(ip, rule_table)
                                    end
                                    challenge_result = {
                                        result = 'fail',
                                        score = challenge_result.score,
                                        reason = '尝试次数过多，请稍后重试'
                                    }
                                end
                            end
                        end
                    end
                end
            end
        end

        -- 协议层失败原因（配合 reqtime/now/window 定位签名与时间窗问题）
        if not detail_protocol then
            if not req_sign then
                detail_protocol = "sign_missing"
            elseif not req_time then
                detail_protocol = "time_missing"
            elseif (req_time + verify_window) < time then
                detail_protocol = "time_expired"
            elseif not sign_pass then
                detail_protocol = "sign_mismatch"
            elseif not detail_payload_field then
                detail_protocol = "payload_missing"
            elseif not detail_payload_ok then
                detail_protocol = "payload_invalid"
            else
                detail_protocol = "payload_ok_no_challenge"
            end
        end

        ngx.header.content_type = "application/json"

        if challenge_result.result ~= 'success' then
            local cid = payload and tostring(payload.challenge_id) or '-'
            -- 用 ERR 级别保证落盘：多数 nginx error_log 未配置级别时默认 error，
            -- WARN/INFO 会被丢弃，导致误杀样本无法排查。
            -- 按 IP 每秒节流：攻击者批量打失败会刷爆日志磁盘，其余降级为计数告警。
            if throttle_allow(key_captcha .. ":logthrottle") then
                ngx.log(ngx.ERR,
                    "captcha cid=", cid,
                    " result=", tostring(challenge_result.result),
                    " score=", tostring(challenge_result.score),
                    " protocol=", tostring(detail_protocol or 'none'),
                    " formula=", tostring(detail_formula or '?'),
                    " browser=", tostring(detail_browser or '?'),
                    " behavior=", tostring(detail_behavior or '?'),
                    " reasons=", tostring(detail_reasons or 'none'),
                    " reason=", tostring(challenge_result.reason or ''),
                    " info=", tostring(detail_info or 'none'),
                    " reqtime=", tostring(req_time or '-'),
                    " now=", tostring(time or '-'),
                    " window=", tostring(verify_window or '-'),
                    " diff=", tostring((req_time and time and (time - req_time)) or '-'),
                    " elapsed=", tostring(detail_elapsed or '-'),
                    " probe=", tostring(detail_probe or 'pass'),
                    " signals=", tostring(detail_signals or '-'),
                    " host=", tostring(ngx.ctx.server_name or ngx.var.host or '-'),
                    " ver=", CAPTCHA_VERSION,
                    " ip=", tostring(ip), " ua=", tostring(ua or ''))
            else
                ngx.log(ngx.WARN, "captcha fail throttled cid=", cid,
                    " result=", tostring(challenge_result.result),
                    " ip=", tostring(ip))
            end
        end

        -- 通过日志：暴露通过者提交的浏览器遥测（info=）与得分构成、服务端计时（elapsed=），
        -- 用于定位"机器人如何通过"。双层节流防刷爆 error.log（见 MAX_CAPTCHA_SUCCESS_LOGS_PER_SEC）。
        -- captcha.successLog=false 可整体关闭。
        if challenge_result.result == 'success' and captcha.successLog ~= false then
            local gcount = store_incr(constants.KEY_CAPTCHA_PREFIX .. "logglobal", 1) or 0
            if gcount <= MAX_CAPTCHA_SUCCESS_LOGS_PER_SEC
                and throttle_allow(key_captcha .. ":successthrottle") then
                ngx.log(ngx.ERR,
                    "captcha-pass cid=", tostring(payload.challenge_id),
                    " result=", tostring(challenge_result.result),
                    " score=", tostring(challenge_result.score),
                    " formula=", tostring(detail_formula or '?'),
                    " browser=", tostring(detail_browser or '?'),
                    " behavior=", tostring(detail_behavior or '?'),
                    " reasons=", tostring(detail_reasons or 'none'),
                    " info=", tostring(detail_info or 'none'),
                    " elapsed=", tostring(detail_elapsed or '-'),
                    " probe=", tostring(detail_probe or 'pass'),
                    " signals=", tostring(detail_signals or '-'),
                    " host=", tostring(ngx.ctx.server_name or ngx.var.host or '-'),
                    " ver=", CAPTCHA_VERSION,
                    " ip=", tostring(ip), " ua=", tostring(ua or ''))
            end
        end

        local data_json = cjson_encode(challenge_result)
        ngx.print(data_json)

        return ngx.exit(ngx.HTTP_OK)
    end

    -- ---- serve 挑战页路径 ----
    -- 冷却期：不再出题
    if store_get(key_cooldown) then
        return too_many_requests()
    end
    -- 出题频率限制：每个 IP 在验证窗口内最多下发 MAX_CHALLENGE_SERVES_PER_WINDOW 次，
    -- 防止攻击者持续刷新挑战页把 nonce/formula 写满共享字典或 Redis（DoS）。
    -- 按 IP 统计（而非 ip+ua+host）：UA 轮换攻击无法绕过；NAT 后多用户共享出口 IP 亦在阈值内。
    -- 注意 check_captcha 会在 pending 期间对页面/子资源请求反复重出题，正常页面子资源数远小于该阈值。
    local key_serve = constants.KEY_CAPTCHA_PREFIX .. "serve:" .. tostring(ip)
    local serve_count = store_incr(key_serve, verify_window) or 0
    if serve_count > MAX_CHALLENGE_SERVES_PER_WINDOW then
        ngx.log(ngx.ERR, "captcha serve limit exceeded for ip=", tostring(ip),
            " count=", tostring(serve_count),
            " window=", tostring(verify_window))
        return too_many_requests()
    end
    -- 标记挑战进行中（初始失败计数 0）；仅验证失败时自增，页面/子资源请求不计
    if store_get(key_captcha) == nil then
        store_set(key_captcha, 0, verify_window)
    end

    local formula, result = get_random_formula()

    -- 生成一次性 challenge_id（nonce），随公式一起缓存并注入 HTML
    -- 验证请求必须携带该 nonce，且无论成功失败均作废，防止 replay 攻击
    -- key 仅由 nonce 决定：并发/重试 serve 互不覆盖，验证只依赖页面注入的 challenge_id
    local challenge_id = upper(md5(key_captcha .. ngx.time() .. tostring(math.random())))
    local challenge_key = constants.KEY_CAPTCHA_PREFIX .. "nonce:" .. challenge_id
    local formula_key = challenge_key .. "/f"
    local challenge_ts = math.floor(ngx.now() * 1000) -- 服务端记录 challenge 生成时间（毫秒）
    local challenge_val = challenge_id .. "_" .. tostring(challenge_ts)
    local formula_val = formula .. "_" .. result
    -- 每次挑战独立的 probe_token：注入挑战页 JS，由其计算出 waf_challenge cookie 值。
    -- 值不在 HTML 中以明文出现，必须执行页面 JS 才能构造；纯 HTTP 脚本（不跑 JS）无法构造。
    local probe_token = upper(md5(challenge_id .. tostring(math.random()) .. tostring(ngx.time())))
    local probe_key = challenge_key .. "/p"

    -- 写入必须成功：nonce/formula/probe 存储失败会导致验证请求全部失效（静默全站打不开），
    -- 这里检查返回值并输出高置信度 ERR 日志，供 nginx error.log 直接定位（redis 掉线 / 共享字典满）
    local ok1, err1, ok2, err2, ok3, err3 = nil, nil, nil, nil, nil, nil
    if is_system_option_on("redis") then
        ok1, err1 = redis_cli.set(challenge_key, challenge_val, verify_window)
        ok2, err2 = redis_cli.set(formula_key, formula_val, verify_window)
        ok3, err3 = redis_cli.set(probe_key, probe_token, verify_window)
    else
        local limit = ngx.shared.dict_captcha
        if limit then
            ok1, err1 = limit:set(challenge_key, challenge_val, verify_window)
            ok2, err2 = limit:set(formula_key, formula_val, verify_window)
            ok3, err3 = limit:set(probe_key, probe_token, verify_window)
        end
    end
    if not (ok1 and ok2 and ok3) then
        -- 满库时直接给出剩余空间：err 通常为 "no memory"，free=0 即共享字典写满
        local cap, free = "-", "-"
        if not is_system_option_on("redis") and ngx.shared.dict_captcha then
            cap = tostring(ngx.shared.dict_captcha:capacity())
            free = tostring(ngx.shared.dict_captcha:free_space())
        end
        ngx.log(ngx.ERR, "captcha storage write failed: cid=", tostring(challenge_id),
            " redis=", tostring(is_system_option_on("redis")),
            " ok_nonce=", tostring(ok1), " err_nonce=", tostring(err1 or '-'),
            " ok_formula=", tostring(ok2), " err_formula=", tostring(err2 or '-'),
            " ok_probe=", tostring(ok3), " err_probe=", tostring(err3 or '-'),
            " window=", tostring(verify_window),
            " cap=", cap, " free=", free,
            " -> challenge page will NOT be verifiable, every user will fail verify")
    end

    _M.clear_access_token()
    ngx.header.content_type = "text/html"
    -- 挑战页含一次性 nonce，严禁被浏览器/CDN/代理缓存；否则用户拿到缓存的旧挑战页，
    -- pending key 不存在，验证 POST 全部兜底放行到源站（表现为 42B 海量洪峰 / 用户验证不过）
    ngx.header["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    ngx.header["Pragma"] = "no-cache"
    ngx.header["Expires"] = "0"

    args["Captcha-Time"] = time

    local sign = _M.get_sign(args, 'Captcha-Sign', SECRET)

    local html = CHALLENGE_HTML
    html = ngxgsub(html, "\\$captcha-sign", sign, "jo")
    html = ngxgsub(html, "\\$captcha-time", tostring(time), "jo")
    html = ngxgsub(html, "\\$formula", formula, "jo")
    html = ngxgsub(html, "\\$challenge-id", challenge_id, "jo")
    html = ngxgsub(html, "\\$probe-token", probe_token, "jo")

    -- 版本注释：curl 挑战页即可确认线上部署的前端/后端版本（排查"线上是旧版"）
    html = html .. "<!-- captcha:ver=" .. CAPTCHA_VERSION .. " -->"

    ngx.print(html)

    return ngx.exit(ngx.HTTP_OK)
end

local function do_captcha(module_name, rule_table)
    ngx.ctx.module_name = module_name
    ngx.ctx.rule_table = rule_table
    ngx.ctx.is_attack = false
    ngx.ctx.is_captcha = true
    ngx.ctx.is_blocked = true

    local captcha_type = upper(rule_table.type)
    if captcha_type == 'JS_CHALLENGE' then
        js_challenge()
    end
end

function _M.trigger_captcha()
    if is_site_option_on("bot") == false then
        return
    end

    local captcha = get_site_config("bot").captcha
    if captcha.state ~= "on" then
        return
    end

    if _M.check_access_token() then
        return
    end

    local ip = ngx.ctx.ip
    local key = constants.KEY_CAPTCHA_PREFIX .. md5(ip .. ngx.ctx.ua .. ngx.ctx.server_name .. SECRET)
    local key_cooldown = key .. ":cooldown"

    -- 冷却期：直接 429，不再出题
    if store_get(key_cooldown) then
        return too_many_requests()
    end

    -- 标记挑战进行中（失败计数初始 0）；页面/子资源请求不计数
    if store_get(key) == nil then
        store_set(key, 0, get_verify_window(captcha))
    end

    local module = get_site_security_modules("captcha")
    local rule_table = module.rules[1]
    do_captcha(module.moduleName, rule_table)
end

function _M.check_captcha()
    if is_site_option_on("bot") == false then
        return
    end

    local captcha = get_site_config("bot").captcha
    if captcha.state ~= "on" then
        return
    end

    -- 环境信标（challenge 页内的隐藏 1x1 图）：记录"页面被真实渲染并加载了子资源"。
    -- 仅当对应 nonce 尚未被消费（挑战进行中）才记录，防止脚本用随机 id 预填信标；
    -- 该请求必须比验证 POST 早发生，纯 HTTP 脚本（从不加载子资源）必然缺失此记录。
    -- 信标值记录请求方 IP：验证时要求与验证 POST 同源（农场把出题/信标/验证拆成多套 IP 分工，
    -- 即使回传 cookie 也会被此关拦下）。真实浏览器三请求同 IP 不受影响。
    if ngx.var.uri == '/captcha/beacon' then
        local c = ngx.var.arg_c
        local challenge_key = c and (constants.KEY_CAPTCHA_PREFIX .. "nonce:" .. c) or nil
        if challenge_key and store_get(challenge_key) then
            store_set(constants.KEY_CAPTCHA_PREFIX .. "beacon:" .. c, tostring(ngx.ctx.ip or ngx.var.remote_addr),
                get_verify_window(captcha))
        end
        ngx.header.content_type = "image/gif"
        ngx.header["Cache-Control"] = "no-store"
        ngx.print(
            "\71\73\70\56\57\97\1\0\1\0\128\0\0\0\0\0\255\255\255\33\249\4\1\0\0\0\0\44\0\0\0\0\1\0\1\0\0\2\2\68\1\0\59")
        return ngx.exit(ngx.HTTP_OK)
    end

    if _M.check_access_token() then
        return
    end

    local ip = ngx.ctx.ip
    local key = constants.KEY_CAPTCHA_PREFIX .. md5(ip .. ngx.ctx.ua .. ngx.ctx.server_name .. SECRET)
    local key_cooldown = key .. ":cooldown"

    -- 冷却期：一律 429
    if store_get(key_cooldown) then
        return too_many_requests()
    end

    -- 挑战进行中：继续出题（不计次数）
    if store_get(key) then
        local module = get_site_security_modules("captcha")
        local rule_table = module.rules[1]
        do_captcha(module.moduleName, rule_table)
    elseif ngx.var.uri == '/captcha/challenge' and ngx.req.get_method() == 'POST' then
        -- 止血 + 诊断：POST 验证但查无 pending key。绝不能放行到源站——
        -- 源站 Resin 对 /captcha/challenge 没有 POST 处理器（只允许 GET/HEAD），放行会回 405，
        -- 导致用户挑战页 JS 拿不到合法响应、挑战永远不过（表现为源站 42B/405 洪峰 + 用户卡死）。
        -- 这里 WAF 无条件接管并返回 fail JSON：挑战页 JS 收到 fail 会 reload 重新出题（重新 serve → 重新种 key），
        -- 下一次 POST 即可正常验证，用户自愈。
        -- 根因（为何无 key）通常是：挑战页被缓存 / verify_window 过期 / 出题与验证的 ip|ua|host 不一致。
        -- 限流：每 IP 60s 内最多记 3 条，避免探测流量打爆 error.log。
        local key_diag = constants.KEY_CAPTCHA_PREFIX .. "diag:" .. tostring(ip)
        local n = store_incr(key_diag, 60)
        if n and n <= 3 then
            ngx.log(ngx.ERR, "captcha fallthrough: no pending key ip=", tostring(ip),
                " host=", tostring(ngx.ctx.server_name),
                " ua=", tostring(ngx.ctx.ua),
                " uri=", tostring(ngx.var.uri))
        end
        ngx.header.content_type = "application/json"
        ngx.print(cjson_encode({ result = "fail", reason = "验证请求无效或已过期，请重新验证" }))
        return ngx.exit(ngx.HTTP_OK)
    end
end

return _M
