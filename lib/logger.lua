local concat = table.concat
local newtab = table.new
local timerat = ngx.timer.at
local setmetatable = setmetatable

local _M = {}

local mt = {__index = _M}

function _M:new(logPath, host, rolling)
    local t = {
            flush_limit = 4096,-- 4kb
            flush_timeout = 1,

            buffered_size = 0,
            buffer_index = 0,
            buffer_data = newtab(20000, 0),

            logPath = logPath,
            prefix = logPath .. host .. '_',
            rolling = rolling or false,
            host = host,
            timer = nil}

    setmetatable(t, mt)
    return t
end

local function needFlush(self)
    if self.buffered_size > 0 then
        return true
    end

    return false
end

local function flushLock(self)
    local dic_lock = ngx.shared.dict_locks
    local locked = dic_lock:get(self.host)
    if not locked then
        local succ, err = dic_lock:set(self.host, true)
        if not succ then
            ngx.log(ngx.ERR, "failed to lock logfile " .. self.host .. ": ", err)
        end
        return succ
    end
    return false
end

local function flushUnlock(self)
    local dic_lock = ngx.shared.dict_locks
    local succ, err = dic_lock:set(self.host, false)
    if not succ then
        ngx.log(ngx.ERR, "failed to unlock logfile " .. self.host .. ": ", err)
    end
    return succ
end

local function writeFile(self, value)
    local fileName = ''
    if self.rolling then
        fileName = self.prefix .. ngx.today() .. ".log"
    else
        fileName = self.logPath
    end
    
	local file = io.open(fileName, "a+")

	if file == nil or value == nil then
		return
	end

	file:write(value)
	file:flush()
	file:close()

	return
end

local function flushBuffer(self)
    if not needFlush(self) then
        return true
    end

    if not flushLock(self) then
        return true
    end

    local buffer = concat(self.buffer_data, "", 1, self.buffer_index)
    writeFile(self, buffer)
    
    self.buffered_size = 0
    self.buffer_index = 0
    self.buffer_data = newtab(20000, 0)
    
    flushUnlock(self)
end

local function flushPeriod(premature, self)
    flushBuffer(self)
    self.timer = false
end

local function writeBuffer(self, msg, msg_len)
    self.buffer_index = self.buffer_index + 1
    
    self.buffer_data[self.buffer_index] = msg    
    
    self.buffered_size = self.buffered_size + msg_len
    
    return self.buffered_size
end

local function startTimer(self)
    if not self.timer then
        local ok, err = timerat(self.flush_timeout, flushPeriod, self)
        if not ok then
            ngx.log(ngx.ERR, "failed to create the timer: ", err)
            return
        end
        if ok then
            self.timer = true         
        end
    end
    return self.timer
end

function _M:log(msg)
    if type(msg) ~= "string" then
        msg = tostring(msg)
    end

    local msg_len = #msg
    local len = msg_len + self.buffered_size

    if len < self.flush_limit then
        writeBuffer(self, msg, msg_len)
        startTimer(self)
    elseif len >= self.flush_limit then
        flushBuffer(self)
    end
end


return _M