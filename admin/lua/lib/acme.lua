-- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
-- Copyright (c) 2024 bukale bukale2022@163.com

-- 免费证书申请与续期。使用 lego 的 HTTP-01 webroot 模式。

local cjson = require "cjson"
local config = require "config"
local file_utils = require "file_utils"
local rule_utils = require "lib.rule_utils"
local site_config = require "lib.site_config"
local x509 = require "lib.x509"
local ffi = require "ffi"

local pairs = pairs
local ipairs = ipairs
local tonumber = tonumber
local tostring = tostring
local type = type
local pcall = pcall
local format = string.format
local gsub = string.gsub
local sub = string.sub
local find = string.find
local match = string.match
local gmatch = string.gmatch
local lower = string.lower
local concat = table.concat
local insert = table.insert
local date = os.date
local time = os.time
local execute = os.execute
local remove = os.remove
local floor = math.floor
local max = math.max
local cjson_decode = cjson.decode
local cjson_encode = cjson.encode

local read_file = file_utils.read_file_to_string
local write_file = file_utils.write_string_to_file
local write_file_atomic = file_utils.write_string_to_file_atomic

local write_binary_file = file_utils.write_binary_to_file
local is_file = file_utils.is_file_exists
local is_directory = file_utils.is_directory
local mkdir = file_utils.mkdir

local _M = {}

local IS_WINDOWS = ffi.os == "Windows"
local ACME_PATH = gsub(config.ZHONGKUI_PATH .. "/data/acme", "\\", "/")
local WEBROOT = ACME_PATH .. "/webroot"
local CERTS_PATH = gsub(config.ZHONGKUI_PATH .. "/admin/ssl-certs/", "\\", "/")
local CERTIFICATE_PATH = config.CONF_PATH .. "/certificate.json"
local WEBSITES_PATH = config.CONF_PATH .. "/website.json"
local SETTINGS_PATH = config.CONF_PATH .. "/acme.json"
local SITES_CONF_PATH = config.ZHONGKUI_PATH .. "/admin/conf/sites.conf"
local RELOAD_MARKER = ACME_PATH .. "/reload_pending"
local LEGO_BIN = gsub(config.ZHONGKUI_PATH .. (IS_WINDOWS and "/bin/lego.exe" or "/bin/lego"), "\\", "/")
local CHALLENGE_PREFIX = "/.well-known/acme-challenge/"
local LEGO_TIMEOUT = 180

-- 操作锁只用于避免并发申请；必须带心跳，避免 worker 异常退出后把后续申请锁死。
local LOCK_KEY = "acme:operation"
local LOCK_TTL = 120
local LOCK_HEARTBEAT_INTERVAL = 5
local current_lock_token = nil
local lock_counter = 0

local CERT_EXTS = {pem = true, crt = true}
local KEY_EXTS = {key = true}

local DEFAULT_SETTINGS = {
    email = "",
    server = "https://acme-v02.api.letsencrypt.org/directory",
    keyType = "RSA2048",
    renewDays = 30,
}

local ALLOWED_SERVERS = {
    ["https://acme-v02.api.letsencrypt.org/directory"] = true,
    ["https://acme-staging-v02.api.letsencrypt.org/directory"] = true,
}

local function trim(value)
    return (gsub(tostring(value or ""), "^%s*(.-)%s*$", "%1"))
end

local function quote(value)
    value = tostring(value)

    if IS_WINDOWS then
        -- batch 文件中 % 需要转义，避免路径或参数中的 %VAR% 被展开
        local escaped = gsub(value, '"', '""')
        escaped = gsub(escaped, "%%", "%%%%")
        return '"' .. escaped .. '"'
    end

    return "'" .. gsub(value, "'", "'\\''") .. "'"
end

local function tail(value, size)
    value = tostring(value or "")
    if #value <= size then
        return value
    end
    return sub(value, -size)
end

local function mkdir_p(path)
    path = gsub(path, "\\", "/")
    path = gsub(path, "/+$", "")
    if path == "" then
        return
    end

    local prefix = ""
    if sub(path, 1, 1) == "/" then
        prefix = "/"
    end

    local drive = match(path, "^(%a:)/")
    if drive then
        prefix = drive .. "/"
        path = sub(path, 4)
    end

    for part in gmatch(path, "[^/]+") do
        if prefix == "" then
            prefix = part
        elseif sub(prefix, -1) == "/" then
            prefix = prefix .. part
        else
            prefix = prefix .. "/" .. part
        end

        if not is_directory(prefix) then
            mkdir(prefix)
        end
    end
end

local function ensure_dirs()
    mkdir_p(ACME_PATH)
    mkdir_p(ACME_PATH .. "/logs")
    mkdir_p(WEBROOT .. "/.well-known/acme-challenge")
    mkdir_p(CERTS_PATH)
end

local function safe_file_name(name)
    name = gsub(tostring(name or "unknown"), "%*", "wildcard")
    return (gsub(name, "[^%w%.%-_]", "_"))
end

local function is_safe_path(path, extensions)
    if not path then
        return false
    end

    path = gsub(path, "\\", "/")
    if sub(path, 1, #CERTS_PATH) ~= CERTS_PATH then
        return false
    end

    local name = sub(path, #CERTS_PATH + 1)
    if name == "" or find(name, "/", 1, true) or find(name, "..", 1, true) then
        return false
    end

    local ext = match(name, "%.([^.]+)$")
    return ext ~= nil and extensions[lower(ext)] == true
end

local function now_string()
    return date("%Y-%m-%d %H:%M:%S")
end

local function cert_files_missing(record)
    return not record.certPath or not record.keyPath
        or not is_file(record.certPath) or not is_file(record.keyPath)
end

local function days_left(date_string)
    if not date_string then
        return nil
    end

    local year, month, day = match(date_string, "^(%d%d%d%d)%-(%d%d)%-(%d%d)$")
    if not year then
        return nil
    end

    local expiration = time({
        year = tonumber(year),
        month = tonumber(month),
        day = tonumber(day),
        hour = 12,
    })

    return (expiration - time()) / 86400
end

local function parse_domains(field)
    local domains = {}
    local seen = {}

    local function add(value)
        local domain = lower(trim(value))
        domain = gsub(domain, "%.+$", "")

        if domain == "" then
            return true
        end

        if find(domain, "*", 1, true) then
            return nil, "暂不支持泛域名证书"
        end

        if #domain > 253 or find(domain, "[^%w%.%-]") or not find(domain, ".", 1, true)
            or sub(domain, 1, 1) == "." or find(domain, "..", 1, true) then
            return nil, "域名格式不正确: " .. domain
        end

        for label in gmatch(domain, "[^.]+") do
            if #label > 63 or sub(label, 1, 1) == "-" or sub(label, -1) == "-" then
                return nil, "域名格式不正确: " .. domain
            end
        end

        if not seen[domain] then
            seen[domain] = true
            insert(domains, domain)
        end

        return true
    end

    local ok, err = add(field.domain)
    if not ok then
        return nil, err
    end

    if #domains == 0 then
        return nil, "请输入域名"
    end

    local extra = field.domains
    if type(extra) == "table" then
        for _, domain in ipairs(extra) do
            ok, err = add(domain)
            if not ok then
                return nil, err
            end
        end
    elseif extra and trim(extra) ~= "" then
        for domain in gmatch(tostring(extra), "[^,%s]+") do
            ok, err = add(domain)
            if not ok then
                return nil, err
            end
        end
    end

    if #domains > 100 then
        return nil, "单个证书最多支持 100 个域名"
    end

    return domains
end

local function validate_email(email)
    email = trim(email)

    if email == "" or #email > 254 then
        return nil, "请输入有效邮箱"
    end

    if find(email, "[%s;\"'&|<>%%!]") or not find(email, "@", 1, true) or not find(email, ".", 1, true) then
        return nil, "请输入有效邮箱"
    end

    return email
end

local function read_certificate_table()
    local json = read_file(CERTIFICATE_PATH)
    if not json then
        return nil
    end

    local ok, result = pcall(cjson_decode, json)
    if not ok or type(result) ~= "table" then
        return nil
    end

    return result
end

local function get_records()
    local result = read_certificate_table()
    return result and result.rules or {}
end

local function get_record(id)
    id = tonumber(id)
    if not id then
        return nil
    end
    return rule_utils.get_rule(CERTIFICATE_PATH, id).data
end

local function find_acme_by_domain(domain)
    for _, record in pairs(get_records()) do
        if record.source == "acme" and lower(record.domainName or "") == domain then
            return record
        end
    end
    return nil
end

local function save_record(record)
    local response = rule_utils.save_or_update_rule(CERTIFICATE_PATH, record)
    if response.code ~= 200 or not record.id then
        return false
    end

    local saved = rule_utils.get_rule(CERTIFICATE_PATH, record.id).data
    return saved ~= nil, saved
end

local function mark_error(record, message)
    if type(record.acme) ~= "table" then
        record.acme = {}
    end
    record.acme.status = "error"
    record.acme.lastAttempt = now_string()
    record.acme.lastError = tail(message or "unknown error", 3000)
    save_record(record)
end

local function domain_configured(domain)
    local json = read_file(WEBSITES_PATH)
    if not json then
        return false
    end

    local ok, result = pcall(cjson_decode, json)
    if not ok or type(result) ~= "table" or not result.rules then
        return false
    end

    for _, site in pairs(result.rules) do
        for _, name in ipairs(site.serverNames or {}) do
            name = lower(tostring(name))
            if name == domain then
                return true
            end

            if sub(name, 1, 2) == "*." then
                local suffix = sub(name, 2)
                if #domain > #suffix and sub(domain, -#suffix) == suffix then
                    return true
                end
            end
        end
    end

    return false
end

local function probe_challenge_route(domain)
    if not ngx.socket or not ngx.socket.tcp then
        return true
    end

    domain = gsub(tostring(domain or ""), "[\r\n]", "")
    if domain == "" then
        return true
    end

    local token = "waf-probe-" .. tostring(time()) .. "-" .. tostring(floor((ngx.now() or 0) * 1000))
    local probe_file = WEBROOT .. CHALLENGE_PREFIX .. token
    local written, write_err = write_binary_file(probe_file, token)
    if not written then
        return nil, "写入 ACME 验证探测文件失败: " .. tostring(write_err)
    end

    local sock = ngx.socket.tcp()
    sock:settimeout(3000)

    local connected, connect_err = sock:connect("127.0.0.1", 80)
    if not connected then
        remove(probe_file)
        return nil, "连接本机 80 端口失败: " .. tostring(connect_err)
    end

    local request = "GET " .. CHALLENGE_PREFIX .. token .. " HTTP/1.0\r\nHost: " .. domain .. "\r\nConnection: close\r\n\r\n"
    local sent, send_err = sock:send(request)
    if not sent then
        sock:close()
        remove(probe_file)
        return nil, "发送 ACME 验证探测请求失败: " .. tostring(send_err)
    end

    local response, recv_err = sock:receive("*a")
    sock:close()
    remove(probe_file)

    if not response then
        return nil, "读取 ACME 验证探测响应失败: " .. tostring(recv_err)
    end

    local status = match(response, "^HTTP/%d%.%d%s+(%d+)")
    if status ~= "200" then
        return nil, "ACME 验证探测返回状态码 " .. tostring(status or "unknown")
    end

    if not find(response, token, 1, true) then
        return nil, "ACME 验证探测响应内容不匹配"
    end

    return true
end

local function new_lock_token()
    lock_counter = lock_counter + 1
    local pid = (ngx.worker and ngx.worker.pid and ngx.worker.pid()) or 0
    return format("%s:%d:%d", tostring(pid), floor((ngx.now() or time()) * 1000), lock_counter)
end

-- 返回锁 token；失败返回 nil。调用方必须把 token 传给 release_lock。
local function acquire_lock()
    local dict = ngx.shared.dict_locks
    local token = new_lock_token()
    if not dict then
        current_lock_token = token
        return token
    end

    local ok = dict:add(LOCK_KEY, token, LOCK_TTL)
    if ok ~= true then
        return nil
    end

    current_lock_token = token
    return token
end

local function release_lock(token)
    local dict = ngx.shared.dict_locks
    if dict then
        -- 只删除自己的锁，避免误删后来者的锁
        if dict:get(LOCK_KEY) == token then
            dict:delete(LOCK_KEY)
        end
    end

    if current_lock_token == token then
        current_lock_token = nil
    end
end

-- 长时间操作期间续期，worker 崩溃后最多等待 LOCK_TTL 秒即可重新申请。
local function touch_lock()
    local token = current_lock_token
    local dict = ngx.shared.dict_locks
    if not token or not dict then
        return
    end

    if dict:get(LOCK_KEY) == token then
        dict:set(LOCK_KEY, token, LOCK_TTL)
    end
end

local function ensure_challenge_ready(domain)
    touch_lock()

    local generated, generate_err = site_config.generate()
    if not generated then
        return nil, "生成站点配置失败: " .. tostring(generate_err)
    end

    local after = read_file(SITES_CONF_PATH) or ""

    if not find(after, CHALLENGE_PREFIX, 1, true) then
        return nil, "站点配置中未找到 ACME 验证路径，请先添加站点"
    end

    -- 这里不比较文件内容：即使内容未变化，也要确保当前 nginx 已经加载验证路径
    touch_lock()
    local reloaded, reload_err = config.reload_config_file()
    if not reloaded then
        write_file(RELOAD_MARKER, now_string())
        return nil, "nginx 重载失败，无法启用 ACME 验证路径: " .. tostring(reload_err or "unknown error")
    end

    remove(RELOAD_MARKER)

    -- reload 是异步生效的，Windows 下新 worker 启动需要时间，这里短轮询等待验证路径生效
    local probed, probe_err
    for attempt = 1, 10 do
        touch_lock()

        if ngx.sleep then
            ngx.sleep(0.3)
        end

        probed, probe_err = probe_challenge_route(domain)
        if probed then
            return true
        end

        if not ngx.sleep then
            break
        end
    end

    write_file(RELOAD_MARKER, now_string())
    return nil, "ACME 验证路径未生效: " .. tostring(probe_err)
end

local function retry_pending_reload()
    if not is_file(RELOAD_MARKER) then
        return
    end

    if config.reload_config_file() ~= false then
        remove(RELOAD_MARKER)
    end
end

-- Windows 下 os.rename 不能覆盖已有文件，使用 MoveFileExW 做原子替换；
-- 失败时退回到 remove + rename。
--
-- lego 必须用 CreateProcessW 直接启动，不能用 os.execute + start：
-- Windows 的 start 打开 .bat 时会以 cmd /K 运行，批处理结束后 shell 不退出；
-- 同时子进程默认继承 nginx 的监听 socket，worker 退出后端口仍被残留进程占用，
-- 表现为后台所有请求（包括再次申请证书）一直没有响应。
local kernel32 = nil
local windows_api_ready = nil

local function init_windows_api()
    if windows_api_ready ~= nil then
        return windows_api_ready
    end

    windows_api_ready = false
    if not IS_WINDOWS then
        return false
    end

    local loaded, lib = pcall(ffi.load, "kernel32")
    if not loaded then
        return false
    end

    -- 统一在这里声明，避免其它模块重复 cdef 同名符号
    pcall(ffi.cdef, [[
        typedef struct {
            unsigned long cb;
            uint16_t *lpReserved;
            uint16_t *lpDesktop;
            uint16_t *lpTitle;
            unsigned long dwX;
            unsigned long dwY;
            unsigned long dwXSize;
            unsigned long dwYSize;
            unsigned long dwXCountChars;
            unsigned long dwYCountChars;
            unsigned long dwFillAttribute;
            unsigned long dwFlags;
            uint16_t wShowWindow;
            uint16_t cbReserved2;
            uint8_t *lpReserved2;
            void *hStdInput;
            void *hStdOutput;
            void *hStdError;
        } zk_startupinfo_w;

        typedef struct {
            void *hProcess;
            void *hThread;
            unsigned long dwProcessId;
            unsigned long dwThreadId;
        } zk_process_information;

        typedef struct {
            int64_t PerProcessUserTimeLimit;
            int64_t PerJobUserTimeLimit;
            uint32_t LimitFlags;
            uint32_t _pad1;
            uintptr_t MinimumWorkingSetSize;
            uintptr_t MaximumWorkingSetSize;
            uint32_t ActiveProcessLimit;
            uint32_t _pad2;
            uintptr_t Affinity;
            uint32_t PriorityClass;
            uint32_t SchedulingClass;
        } zk_job_basic_limit;

        typedef struct {
            uint64_t ReadOperationCount;
            uint64_t WriteOperationCount;
            uint64_t OtherOperationCount;
            uint64_t ReadTransferCount;
            uint64_t WriteTransferCount;
            uint64_t OtherTransferCount;
        } zk_job_io_counters;

        typedef struct {
            zk_job_basic_limit BasicLimitInformation;
            zk_job_io_counters IoInfo;
            uintptr_t ProcessMemoryLimit;
            uintptr_t JobMemoryLimit;
            uintptr_t PeakProcessMemoryUsed;
            uintptr_t PeakJobMemoryUsed;
        } zk_job_extended_limit;

        int MoveFileExW(const uint16_t *lpExistingFileName, const uint16_t *lpNewFileName, unsigned long dwFlags);
        int MultiByteToWideChar(unsigned int CodePage, unsigned long dwFlags, const char *lpMultiByteStr, int cbMultiByte, uint16_t *lpWideCharStr, int cchWideChar);
        int CreateProcessW(const uint16_t *lpApplicationName, uint16_t *lpCommandLine, void *lpProcessAttributes, void *lpThreadAttributes, int bInheritHandles, unsigned long dwCreationFlags, void *lpEnvironment, const uint16_t *lpCurrentDirectory, zk_startupinfo_w *lpStartupInfo, zk_process_information *lpProcessInformation);
        void *CreateJobObjectW(void *lpJobAttributes, const uint16_t *lpName);
        int SetInformationJobObject(void *hJob, int JobObjectInformationClass, void *lpJobObjectInformation, unsigned int cbJobObjectInformationLength);
        int AssignProcessToJobObject(void *hJob, void *hProcess);
        int TerminateJobObject(void *hJob, unsigned int uExitCode);
        unsigned long ResumeThread(void *hThread);
        unsigned long WaitForSingleObject(void *hHandle, unsigned long dwMilliseconds);
        int TerminateProcess(void *hProcess, unsigned int uExitCode);
        int CloseHandle(void *hObject);
    ]])

    local initialized = pcall(function()
        if not lib.MultiByteToWideChar or not lib.MoveFileExW or not lib.CreateProcessW then
            error("kernel32 symbols not found")
        end
    end)

    if initialized then
        kernel32 = lib
        windows_api_ready = true
    end

    return windows_api_ready
end

local function to_utf16(value)
    value = tostring(value or "")
    if not init_windows_api() then
        return nil
    end

    local length = #value
    local buffer = ffi.new("uint16_t[?]", length + 1)
    if length > 0 then
        if kernel32.MultiByteToWideChar(65001, 0, value, length, buffer, length) == 0 then
            return nil
        end
    end

    buffer[length] = 0
    return buffer
end

local function move_file_ex(source, target)
    if not init_windows_api() then
        return false
    end

    local source_buffer = to_utf16(source)
    local target_buffer = to_utf16(target)
    if not source_buffer or not target_buffer then
        return false
    end

    return kernel32.MoveFileExW(source_buffer, target_buffer, 9) ~= 0
end

-- 启动子进程：不继承任何句柄（bInheritHandles = 0），不显示控制台窗口。
-- 子进程加入 Job Object，并设置 KILL_ON_JOB_CLOSE：
-- worker 崩溃/退出时，cmd.exe 及 lego.exe 子进程树会一起被系统回收。
local function create_kill_job()
    local job = kernel32.CreateJobObjectW(nil, nil)
    if job == nil or job == ffi.NULL then
        return nil
    end

    local info = ffi.new("zk_job_extended_limit")
    info.BasicLimitInformation.LimitFlags = 0x00002000 -- JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE

    if kernel32.SetInformationJobObject(job, 9, info, ffi.sizeof(info)) == 0 then
        kernel32.CloseHandle(job)
        return nil
    end

    return job
end

local function launch_process(command)
    if not init_windows_api() then
        return nil, "当前环境不支持 Windows 进程 API"
    end

    local command_buffer = to_utf16(command)
    if not command_buffer then
        return nil, "无法转换启动命令"
    end

    local startup = ffi.new("zk_startupinfo_w")
    startup.cb = ffi.sizeof(startup)

    local info = ffi.new("zk_process_information")
    local CREATE_NO_WINDOW = 0x08000000
    local CREATE_SUSPENDED = 0x00000004
    local job = create_kill_job()
    local flags = CREATE_NO_WINDOW

    if job then
        -- 先挂起创建，确保没有任何子进程在加入 Job 前被启动
        flags = flags + CREATE_SUSPENDED
    end

    if kernel32.CreateProcessW(nil, command_buffer, nil, nil, 0, flags,
        nil, nil, startup, info) == 0 then
        if job then
            kernel32.CloseHandle(job)
        end
        return nil, "CreateProcessW 失败"
    end

    if job then
        if kernel32.AssignProcessToJobObject(job, info.hProcess) == 0 then
            -- 当前环境不支持嵌套 Job 时退回普通进程，至少保证不会卡住调用方
            kernel32.CloseHandle(job)
            job = nil
        end

        if kernel32.ResumeThread(info.hThread) == 0xFFFFFFFF then
            kernel32.TerminateProcess(info.hProcess, 1)
            kernel32.CloseHandle(info.hThread)
            kernel32.CloseHandle(info.hProcess)
            if job then
                kernel32.CloseHandle(job)
            end
            return nil, "ResumeThread 失败"
        end
    end

    kernel32.CloseHandle(info.hThread)

    return {handle = info.hProcess, job = job, pid = tonumber(info.dwProcessId)}
end

local function process_exited(process)
    if type(process) ~= "table" or not process.handle then
        return false
    end

    -- WAIT_OBJECT_0
    return kernel32.WaitForSingleObject(process.handle, 0) == 0
end

local function stop_process(process, kill_tree)
    if type(process) ~= "table" then
        return
    end

    -- 给 cmd /c 一点时间自然退出，避免截断日志文件
    for _ = 1, 3 do
        if process_exited(process) then
            break
        end
        if ngx.sleep then
            ngx.sleep(0.05)
        end
    end

    if kill_tree then
        if process.job then
            -- 超时/异常退出：连同 lego.exe 一起结束
            kernel32.TerminateJobObject(process.job, 1)
        elseif IS_WINDOWS and process.pid then
            -- 极端情况下 Job 不可用，退回 taskkill 结束进程树
            execute("taskkill /PID " .. tostring(process.pid) .. " /T /F >nul 2>&1")
        end
    end

    -- Linux 下没有进程句柄，用启动时记录的 PID 结束 shell 和 lego
    if process.pid_path then
        local pid = trim(read_file(process.pid_path) or "")
        if kill_tree and match(pid, "^%d+$") then
            execute("pkill -TERM -P " .. pid .. " >/dev/null 2>&1; kill -TERM " .. pid .. " >/dev/null 2>&1")
        end
        remove(process.pid_path)
        process.pid_path = nil
    end

    if process.handle and not process_exited(process) then
        kernel32.TerminateProcess(process.handle, 1)
    end

    if process.job then
        -- KILL_ON_JOB_CLOSE 会顺带清理仍在运行的子进程
        kernel32.CloseHandle(process.job)
        process.job = nil
    end

    if process.handle then
        kernel32.CloseHandle(process.handle)
        process.handle = nil
    end
end

local function replace_file(source, target)
    if IS_WINDOWS and move_file_ex(source, target) then
        return true
    end

    local ok, err = os.rename(source, target)
    if ok then
        return true
    end

    if IS_WINDOWS then
        remove(target)
        ok, err = os.rename(source, target)
    end

    return ok, err
end

local function write_pair_atomic(cert_pem, key_pem, cert_path, key_path)
    local cert_tmp = cert_path .. ".tmp"
    local key_tmp = key_path .. ".tmp"

    local write_ok, write_err = write_binary_file(cert_tmp, cert_pem)
    if write_ok then
        write_ok, write_err = write_binary_file(key_tmp, key_pem)
    end
    if not write_ok then
        remove(cert_tmp)
        remove(key_tmp)
        return nil, "写入临时证书文件失败: " .. tostring(write_err)
    end

    if read_file(cert_tmp, true) ~= cert_pem or read_file(key_tmp, true) ~= key_pem then
        remove(cert_tmp)
        remove(key_tmp)
        return nil, "写入临时证书文件失败"
    end

    local old_cert = read_file(cert_path, true)
    local old_key = read_file(key_path, true)

    local ok, err = replace_file(cert_tmp, cert_path)
    if not ok then
        if old_cert then
            write_binary_file(cert_path, old_cert)
        else
            remove(cert_path)
        end
        remove(cert_tmp)
        remove(key_tmp)
        return nil, "替换证书文件失败: " .. tostring(err)
    end

    ok, err = replace_file(key_tmp, key_path)
    if not ok then
        if old_cert then
            write_binary_file(cert_path, old_cert)
        else
            remove(cert_path)
        end
        if old_key then
            write_binary_file(key_path, old_key)
        else
            remove(key_path)
        end
        remove(cert_tmp)
        remove(key_tmp)
        return nil, "替换私钥文件失败: " .. tostring(err)
    end

    remove(cert_tmp)
    remove(key_tmp)

    if not IS_WINDOWS then
        execute("chmod 600 " .. quote(key_path) .. " 2>/dev/null")
    end

    return true
end

local function build_lego_args(settings, cert_name, domains, force)
    local args = {
        LEGO_BIN,
        -- v5 的日志参数是全局参数，必须放在 run 之前
        "--log.format", "text",
        "run",
        "--accept-tos",
        "--email", settings.email,
        "--server", settings.server,
        "--path", ACME_PATH,
        "--http",
        "--http.webroot", WEBROOT,
        "--key-type", settings.keyType,
        "--cert.name", cert_name,
        "--renew-days", tostring(settings.renewDays),
        "--cert.timeout", "60",
        "--http-timeout", "60",
        "--no-random-sleep",
        "--force-cert-domains",
        "--user-agent", "ZhongKui-WAF/1.0",
    }

    if force then
        insert(args, "--renew-force")
    end

    for _, domain in ipairs(domains) do
        insert(args, "--domains")
        insert(args, domain)
    end

    return args
end

local function run_lego(args)
    ensure_dirs()

    local stamp = tostring(time()) .. "_" .. tostring(floor((ngx.now() or 0) * 1000))
    local script_path = ACME_PATH .. "/run_" .. stamp .. (IS_WINDOWS and ".bat" or ".sh")
    local log_path = ACME_PATH .. "/logs/run_" .. stamp .. ".log"
    local status_path = ACME_PATH .. "/logs/run_" .. stamp .. ".status"

    local command_parts = {}
    for _, value in ipairs(args) do
        insert(command_parts, quote(value))
    end
    local command = concat(command_parts, " ")

    local script
    if IS_WINDOWS then
        script = concat({
            "@echo off",
            "chcp 65001 >nul",
            command .. " > " .. quote(log_path) .. " 2>&1",
            "echo %ERRORLEVEL% > " .. quote(status_path),
        }, "\r\n")
    else
        -- Linux 下再加一层 timeout，即使 nginx 侧等待逻辑异常，lego 也不会永久挂着
        local timeout_seconds = max(30, LEGO_TIMEOUT - 5)
        script = concat({
            "#!/bin/sh",
            "if command -v timeout >/dev/null 2>&1; then",
            "  timeout " .. tostring(timeout_seconds) .. " " .. command .. " > " .. quote(log_path) .. " 2>&1",
            "else",
            "  " .. command .. " > " .. quote(log_path) .. " 2>&1",
            "fi",
            "echo $? > " .. quote(status_path),
        }, "\n")
    end

    local written, write_err = write_binary_file(script_path, script)
    if not written then
        return 1, "无法写入 lego 执行脚本: " .. tostring(write_err)
    end

    if not ngx.sleep then
        remove(script_path)
        return 1, "当前环境不支持异步等待 lego"
    end

    local process
    local pid_path = script_path .. ".pid"
    if IS_WINDOWS then
        -- 直接用 cmd /c 执行批处理，CreateProcessW 不继承句柄，也不使用 start，
        -- 避免残留 cmd /K 进程占用 nginx 监听端口
        local windows_script = gsub(script_path, "/", "\\")
        local launch_err
        process, launch_err = launch_process('cmd.exe /c ""' .. windows_script .. '""')
        if not process then
            remove(script_path)
            return 1, "启动 lego 失败: " .. tostring(launch_err)
        end
    else
        remove(pid_path)
        local launched = execute('nohup sh ' .. quote(script_path) .. ' >/dev/null 2>&1 & echo $! > ' .. quote(pid_path))
        if launched == false or launched == nil or (type(launched) == "number" and launched ~= 0) then
            remove(script_path)
            remove(pid_path)
            return 1, "启动 lego 失败: " .. tostring(launched)
        end
        -- 记录 shell PID，超时/异常时用于结束 lego 子进程
        process = {pid_path = pid_path}
    end

    local started = ngx.now() or time()
    local deadline = started + LEGO_TIMEOUT
    local last_touch = started
    local status
    local timed_out = false

    while true do
        status = read_file(status_path)
        if status then
            break
        end

        local now = ngx.now() or time()

        -- 进程已退出但还没读到状态文件时，给文件系统一点刷盘时间再放弃
        if process and process_exited(process) then
            for _ = 1, 10 do
                status = read_file(status_path)
                if status then
                    break
                end
                ngx.sleep(0.2)
            end
            break
        end

        if now >= deadline then
            timed_out = true
            break
        end

        -- 长时间执行期间续期操作锁，避免被误判为死锁
        if now - last_touch >= LOCK_HEARTBEAT_INTERVAL then
            touch_lock()
            last_touch = now
        end

        ngx.sleep(0.2)
    end

    local code = tonumber(match(status or "", "%-?%d+"))
    local output = read_file(log_path) or ""

    -- 超时必须结束整棵进程树；正常结束也要关闭 Job，顺带清理残留子进程
    stop_process(process, timed_out)

    if timed_out then
        -- 给文件系统一点时间把已写入的日志刷盘
        ngx.sleep(0.2)
        output = read_file(log_path) or output
    end

    if not code then
        local reason
        if timed_out then
            reason = "lego 执行超时（" .. tostring(LEGO_TIMEOUT) .. " 秒）"
        elseif status then
            reason = "lego 未返回有效状态码"
        else
            reason = "lego 进程异常退出（未写入状态码）"
        end

        output = output .. "\n" .. reason
        ngx.log(ngx.ERR, "lego execution failed: ", reason, " script=", script_path)
    end

    -- 无论成功失败都保留最后一份日志，并清理本次运行的临时文件
    write_file(ACME_PATH .. "/logs/last.log", output)
    remove(script_path)
    remove(status_path)
    remove(log_path)
    remove(pid_path)

    return code or 1, output
end

local function read_lego_files(cert_name)
    local base = ACME_PATH .. "/certificates/" .. cert_name
    local cert_pem = read_file(base .. ".crt", true)
    local key_pem = read_file(base .. ".key", true)

    if not cert_pem or not key_pem then
        return nil, nil, "lego 未生成证书文件"
    end

    return cert_pem, key_pem
end

local function import_record(record, cert_pem, key_pem, cert_name, domains, settings, auto_renew)
    local info, err = x509.parse(cert_pem)
    if not info then
        return nil, "证书解析失败: " .. tostring(err)
    end

    if not info.expirationDate then
        return nil, "证书有效期解析失败"
    end

    local cert_path = record.certPath
    local key_path = record.keyPath

    if not (is_safe_path(cert_path, CERT_EXTS) and is_safe_path(key_path, KEY_EXTS)) then
        local base = CERTS_PATH .. "acme_" .. date("%Y%m%d%H%M%S") .. "_" .. safe_file_name(record.domainName)
        cert_path = base .. ".pem"
        key_path = base .. ".key"
    end

    local old_cert = read_file(cert_path, true)
    local old_key = read_file(key_path, true)
    local ok, write_err = write_pair_atomic(cert_pem, key_pem, cert_path, key_path)
    if not ok then
        return nil, write_err
    end

    -- 在副本上更新，保存失败时不要污染调用方手里的旧记录
    local updated = {}
    for key, value in pairs(record) do
        updated[key] = value
    end
    if type(record.acme) == "table" then
        updated.acme = {}
        for key, value in pairs(record.acme) do
            updated.acme[key] = value
        end
    else
        updated.acme = {}
    end

    updated.domainName = updated.domainName or info.domainName
    updated.serial = info.serial
    updated.effectiveDate = info.effectiveDate
    updated.expirationDate = info.expirationDate
    updated.issuerName = info.issuerName or "Let's Encrypt"
    updated.issuerOrgName = info.issuerOrgName
    updated.source = "acme"
    updated.autoRenew = auto_renew ~= false
    updated.certPath = cert_path
    updated.keyPath = key_path
    updated.acme.certName = cert_name
    updated.acme.domains = domains
    updated.acme.email = settings.email
    updated.acme.server = settings.server
    updated.acme.keyType = settings.keyType
    updated.acme.lastAttempt = now_string()
    updated.acme.lastRenewed = now_string()
    updated.acme.lastChecked = now_string()
    updated.acme.status = "active"
    updated.acme.lastError = nil
    updated.publicKey = nil
    updated.privateKey = nil
    updated.file = nil

    local saved, saved_record = save_record(updated)
    if not saved or not saved_record or saved_record.certPath ~= cert_path then
        if old_cert then
            write_binary_file(cert_path, old_cert)
        else
            remove(cert_path)
        end
        if old_key then
            write_binary_file(key_path, old_key)
        else
            remove(key_path)
        end
        return nil, "保存证书配置失败"
    end

    record = saved_record

    -- 证书文件可能刚恢复，重新生成站点配置以便重新启用之前跳过的 SSL 端口
    touch_lock()
    local generated, generate_err = site_config.generate()
    if not generated then
        write_file(RELOAD_MARKER, now_string())
        return true, record, "证书已保存，但站点配置写入失败: " .. tostring(generate_err)
    end

    touch_lock()
    local reloaded, reload_err = config.reload_config_file()
    if not reloaded then
        write_file(RELOAD_MARKER, now_string())
        return true, record, "证书已保存，但 nginx 重载失败，请手动重载: " .. tostring(reload_err or "unknown error")
    end

    remove(RELOAD_MARKER)
    return true, record
end

local function do_apply(settings, domains, email, auto_renew)
    ensure_dirs()

    settings.email = email

    local existing = find_acme_by_domain(domains[1])
    if existing then
        return {code = 400, msg = "该主域名已有免费证书，请直接续期或删除后重新申请"}
    end

    for _, domain in ipairs(domains) do
        if not domain_configured(domain) then
            return {code = 400, msg = "域名 [" .. domain .. "] 尚未在防护站点中配置"}
        end
    end

    if not is_file(LEGO_BIN) then
        return {code = 500, msg = "未找到 lego，请先执行安装脚本下载并校验 lego"}
    end

    -- 校验通过后再落盘，避免无效请求写入配置
    local saved_settings, settings_err = _M.save_settings(settings)
    if not saved_settings then
        return {code = 500, msg = "保存 ACME 配置失败: " .. tostring(settings_err)}
    end

    local ready, ready_err = ensure_challenge_ready(domains[1])
    if not ready then
        return {code = 500, msg = ready_err}
    end

    local cert_name = safe_file_name(domains[1])
    local code, log = run_lego(build_lego_args(settings, cert_name, domains, false))
    if code ~= 0 then
        return {code = 500, msg = "证书申请失败：" .. tail(log, 3000)}
    end

    local cert_pem, key_pem, read_err = read_lego_files(cert_name)
    if not cert_pem then
        return {code = 500, msg = read_err}
    end

    local record = {
        domainName = domains[1],
        source = "acme",
        autoRenew = auto_renew ~= false,
    }

    local ok, result, warning = import_record(record, cert_pem, key_pem, cert_name, domains, settings, auto_renew)
    if not ok then
        return {code = 500, msg = result}
    end

    return {code = 200, data = result, msg = warning or "证书申请成功，请到防护站点手动绑定证书"}
end

function _M.get_settings()
    local settings = {
        email = DEFAULT_SETTINGS.email,
        server = DEFAULT_SETTINGS.server,
        keyType = DEFAULT_SETTINGS.keyType,
        renewDays = DEFAULT_SETTINGS.renewDays,
    }

    local json = read_file(SETTINGS_PATH)
    if json then
        local ok, saved = pcall(cjson_decode, json)
        if ok and type(saved) == "table" then
            settings.email = trim(saved.email)
            settings.server = saved.server or settings.server
            settings.keyType = saved.keyType or settings.keyType
            settings.renewDays = tonumber(saved.renewDays) or settings.renewDays
        end
    end

    if not ALLOWED_SERVERS[settings.server] then
        settings.server = DEFAULT_SETTINGS.server
    end

    if settings.keyType ~= "RSA2048" and settings.keyType ~= "EC256" then
        settings.keyType = DEFAULT_SETTINGS.keyType
    end

    settings.renewDays = math.min(60, math.max(1, settings.renewDays))
    return settings
end

function _M.save_settings(settings)
    settings = settings or _M.get_settings()
    local ok, err = write_file_atomic(SETTINGS_PATH, cjson_encode({
        email = settings.email or "",
        server = settings.server or DEFAULT_SETTINGS.server,
        keyType = settings.keyType or DEFAULT_SETTINGS.keyType,
        renewDays = settings.renewDays or DEFAULT_SETTINGS.renewDays,
    }))
    if not ok then
        ngx.log(ngx.ERR, "failed to save ACME settings: ", tostring(err))
    end
    return ok, err
end

function _M.settings_response()
    local settings = _M.get_settings()
    return {
        code = 200,
        data = {
            email = settings.email,
            server = settings.server,
            keyType = settings.keyType,
            renewDays = settings.renewDays,
        },
        msg = "",
    }
end

function _M.apply(field)
    field = field or {}
    if type(field) ~= "table" then
        return {code = 400, msg = "请求参数格式错误"}
    end

    local domains, domain_err = parse_domains(field)
    if not domains then
        return {code = 400, msg = domain_err}
    end

    local email, email_err = validate_email(field.email)
    if not email then
        return {code = 400, msg = email_err}
    end

    local auto_renew = not (field.autoRenew == false or field.autoRenew == "off" or field.autoRenew == "0")
    local settings = _M.get_settings()

    local lock_token = acquire_lock()
    if not lock_token then
        return {code = 429, msg = "已有证书任务正在执行，请稍后重试"}
    end

    local ok, result = pcall(do_apply, settings, domains, email, auto_renew)
    release_lock(lock_token)

    if not ok then
        ngx.log(ngx.ERR, "ACME apply failed: ", result)
        return {code = 500, msg = "证书申请失败: " .. tostring(result)}
    end

    return result
end

local function do_renew(record, settings, domains, force)
    ensure_dirs()

    local ready, ready_err = ensure_challenge_ready(domains[1])
    if not ready then
        mark_error(record, ready_err)
        return {code = 500, msg = ready_err}
    end

    -- lego 会通过 SanitizedName 将证书 ID 转成小写文件名
    local cert_name = record.acme and record.acme.certName
    if type(cert_name) == "string" then
        cert_name = lower(cert_name)
    end
    if type(cert_name) ~= "string" or not match(cert_name, "^[%w%.%-_]+$") then
        cert_name = lower(safe_file_name(record.domainName))
    end
    local code, log = run_lego(build_lego_args(settings, cert_name, domains, force))
    if code ~= 0 then
        local message = "证书续期失败：" .. tail(log, 3000)
        mark_error(record, message)
        return {code = 500, msg = message}
    end

    local cert_pem, key_pem, read_err = read_lego_files(cert_name)
    if not cert_pem then
        mark_error(record, read_err)
        return {code = 500, msg = read_err}
    end

    local info = x509.parse(cert_pem)
    if info and info.serial and record.serial and info.serial == record.serial
        and not cert_files_missing(record) then
        if type(record.acme) ~= "table" then
            record.acme = {}
        end
        record.acme.lastAttempt = now_string()
        record.acme.lastChecked = now_string()
        record.acme.status = "active"
        record.acme.lastError = nil
        save_record(record)
        return {code = 200, msg = "证书未发生变化", data = {notRenewed = true}}
    end

    local ok, result, warning = import_record(record, cert_pem, key_pem, cert_name, domains, settings, record.autoRenew)
    if not ok then
        mark_error(record, "导入证书失败: " .. tostring(result))
        return {code = 500, msg = "导入证书失败: " .. tostring(result)}
    end

    return {code = 200, data = result, msg = warning or "证书续期成功"}
end

function _M.renew(id, force)
    id = tonumber(id)
    if not id then
        return {code = 400, msg = "证书 ID 无效"}
    end

    local record = get_record(id)
    if not record or record.source ~= "acme" then
        return {code = 400, msg = "不是免费证书"}
    end

    local settings = _M.get_settings()
    local acme = record.acme
    if type(acme) ~= "table" then
        acme = {}
    end
    local email = acme.email or settings.email
    if not email or email == "" then
        return {code = 400, msg = "缺少 ACME 邮箱，请重新申请"}
    end
    settings.email = email
    if ALLOWED_SERVERS[acme.server] then
        settings.server = acme.server
    end
    if acme.keyType == "RSA2048" or acme.keyType == "EC256" then
        settings.keyType = acme.keyType
    end

    local domains = acme.domains
    if type(domains) ~= "table" or #domains == 0 then
        domains = {record.domainName}
    end

    local days = days_left(record.expirationDate)
    if not force and not cert_files_missing(record) and days and days > settings.renewDays then
        return {
            code = 200,
            msg = format("证书尚未到续期时间，剩余 %d 天", max(0, floor(days))),
            data = {notDue = true, daysLeft = days},
        }
    end

    if not is_file(LEGO_BIN) then
        return {code = 500, msg = "未找到 lego，请先执行安装脚本下载并校验 lego"}
    end

    local lock_token = acquire_lock()
    if not lock_token then
        return {code = 429, msg = "已有证书任务正在执行，请稍后重试"}
    end

    -- 只有用户显式强制续期时才传 --renew-force；自动续期优先复用 lego 本地证书，避免重复签发
    local ok, result = pcall(do_renew, record, settings, domains, force == true)
    release_lock(lock_token)

    if not ok then
        ngx.log(ngx.ERR, "ACME renew failed: ", result)
        -- 记录失败也要容错：这里再出错不能让请求直接崩成 HTML 500
        pcall(mark_error, record, tostring(result))
        return {code = 500, msg = "证书续期失败: " .. tostring(result)}
    end

    return result
end

function _M.renew_due()
    retry_pending_reload()

    local settings = _M.get_settings()
    local records = get_records()
    local checked, renewed, failed = 0, 0, 0

    for _, record in ipairs(records) do
        if record.source == "acme" and record.autoRenew ~= false then
            checked = checked + 1
            local days = days_left(record.expirationDate)

            if days == nil or days <= settings.renewDays or cert_files_missing(record) then
                -- 单个证书失败不能中断其它证书的续期
                local called, result = pcall(_M.renew, record.id, false)
                if not called then
                    ngx.log(ngx.ERR, "ACME renew crashed for id ", tostring(record.id), ": ", tostring(result))
                    result = {code = 500, msg = tostring(result)}
                end

                if result and result.code == 200 then
                    local data = result.data or {}
                    if not data.notRenewed and not data.notDue then
                        renewed = renewed + 1
                    end
                else
                    failed = failed + 1
                end
            end
        end
    end

    return {
        code = 200,
        data = {checked = checked, renewed = renewed, failed = failed},
        msg = "",
    }
end

function _M.start_auto_renew()
    if ngx.worker.id() ~= 0 then
        return
    end

    math.randomseed(time() + (ngx.worker.pid() or 0))

    local function handler(premature)
        if premature then
            return
        end

        local ok, result = pcall(_M.renew_due)
        if not ok then
            ngx.log(ngx.ERR, "ACME auto renew failed: ", result)
        elseif result and result.data and result.data.failed > 0 then
            ngx.log(ngx.ERR, "ACME auto renew: checked=", result.data.checked,
                ", renewed=", result.data.renewed, ", failed=", result.data.failed)
        end
    end

    local ok, err = ngx.timer.at(60 + math.random(0, 1800), handler)
    if not ok then
        ngx.log(ngx.ERR, "failed to create ACME timer: ", err)
    end

    local ok2, err2 = ngx.timer.every(12 * 3600, handler)
    if not ok2 then
        ngx.log(ngx.ERR, "failed to create ACME periodic timer: ", err2)
    end
end

function _M.remove_cert_data(record)
    if not record or record.source ~= "acme" then
        return
    end

    local cert_name = record.acme and record.acme.certName
    if type(cert_name) ~= "string" or cert_name == "" then
        if type(record.domainName) ~= "string" or record.domainName == "" then
            return
        end
        cert_name = safe_file_name(record.domainName)
    end

    cert_name = lower(cert_name)
    if not match(cert_name, "^[%w%.%-_]+$") then
        return
    end

    local base = ACME_PATH .. "/certificates/" .. cert_name
    remove(base .. ".crt")
    remove(base .. ".key")
    remove(base .. ".pem")
    remove(base .. ".pfx")
    remove(base .. ".issuer.crt")
    remove(base .. ".json")
end

return _M
