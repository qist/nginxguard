--waf core lib
require 'config'

--Cache via ngx.shared.dict, fallback to direct read if not configured
local waf_cache = ngx.shared.waf_cache

--File modification time detection
--Uses LuaJIT FFI (built into OpenResty) to call libc stat() — no extra module needed
--Fallback: file size + TTL if FFI unavailable
local get_file_mtime
local mtime_reliable = false

do
    local ok_ffi, ffi = pcall(require, "ffi")
    if ok_ffi then
        -- Define a minimal struct to read st_mtime on Linux 64-bit (x86_64 & aarch64)
        -- st_mtime is at byte offset 88 in struct stat; total struct is 144 bytes
        pcall(ffi.cdef, [[
            struct waf_stat_t {
                long long _pad_to_mtime[11];
                long long st_mtime;
                long long _rest[7];
            };
            int stat(const char *path, struct waf_stat_t *buf);
            int __xstat(int ver, const char *path, struct waf_stat_t *buf);
        ]])

        local buf = ffi.new("struct waf_stat_t")
        local do_stat

        -- Try stat() (modern glibc 2.33+ or musl libc)
        pcall(function()
            if ffi.C.stat("/dev/null", buf) == 0 then
                do_stat = function(path)
                    local b = ffi.new("struct waf_stat_t")
                    if ffi.C.stat(path, b) == 0 then
                        return tonumber(b.st_mtime)
                    end
                    return nil
                end
            end
        end)

        -- Try __xstat (older glibc: _STAT_VER_LINUX = 1 on x86_64, 0 on aarch64)
        if not do_stat then
            pcall(function()
                for _, ver in ipairs({1, 0, 3}) do
                    if ffi.C.__xstat(ver, "/dev/null", buf) == 0 then
                        do_stat = function(path)
                            local b = ffi.new("struct waf_stat_t")
                            if ffi.C.__xstat(ver, path, b) == 0 then
                                return tonumber(b.st_mtime)
                            end
                            return nil
                        end
                        break
                    end
                end
            end)
        end

        if do_stat then
            get_file_mtime = do_stat
            mtime_reliable = true
        end
    end
end

-- Fallback: file size (less reliable, combined with TTL as safety net)
if not get_file_mtime then
    get_file_mtime = function(filepath)
        local io = require 'io'
        local f = io.open(filepath, "r")
        if f == nil then return nil end
        local size = f:seek("end")
        f:close()
        return size
    end
end

--Cache TTL: 0 when mtime is reliable (FFI stat available);
--60s when using file-size fallback (forces periodic re-read)
local cache_ttl = mtime_reliable and 0 or 60

--Convert glob-style wildcard pattern to regex
--192.168.0.* → ^192\.168\.0\.\d+$
--192.168.*.1  → ^192\.168\.\d+\.1$
--If no * found, return as-is (already regex)
function glob_to_regex(pattern)
    if pattern == nil or pattern == "" then
        return pattern
    end
    -- no wildcard, treat as regex
    if not string.find(pattern, "%*") then
        return pattern
    end
    -- escape special regex chars except * (prepend backslash)
    local regex = string.gsub(pattern, "([%.%+%-%?%[%]%(%)%$%^])", "\\%1")
    -- replace * with \d+
    regex = string.gsub(regex, "%*", "\\d+")
    -- anchor full match
    return "^" .. regex .. "$"
end

--Get the client IP
--When trust_proxy_headers="on": extract from X-Forwarded-For/X-Real-IP/CF-Connecting-IP
--When trust_proxy_headers="off": only use remote_addr (prevent IP spoofing)
--Supports per-domain override via domain.json
function get_client_ip()
    if ngx.ctx._client_ip then
        return ngx.ctx._client_ip
    end
    local ip
    if get_effective_config("trust_proxy_headers") ~= "off" then
        local headers = ngx.req.get_headers()
        -- 1. CF-Connecting-IP (Cloudflare specific, most reliable)
        ip = headers["CF_Connecting_IP"] or headers["cf-connecting-ip"]
        -- 2. X-Real-IP
        if ip == nil then
            ip = headers["X_real_ip"] or headers["X-Real-IP"]
        end
        -- 3. X-Forwarded-For (take first IP if multiple)
        if ip == nil then
            local xff = headers["X_Forwarded_For"] or headers["X-Forwarded-For"]
            if xff then
                -- extract first IP: "103.119.132.48, 162.158.179.193" → "103.119.132.48"
                ip = string.match(xff, "^%s*([%d%.:%a]+)")
            end
        end
    end
    -- 4. remote_addr (always available, or fallback when headers not trusted)
    if ip == nil then
        ip = ngx.var.remote_addr
    end
    if ip == nil then
        ip = "unknown"
    end
    ngx.ctx._client_ip = ip
    return ip
end

--Get the client user agent
function get_user_agent()
    USER_AGENT = ngx.var.http_user_agent
    if USER_AGENT == nil then
       USER_AGENT = "unknown"
    end
    return USER_AGENT
end

--Get the request domain (strip port from host)
function get_domain()
    if ngx.ctx._domain then
        return ngx.ctx._domain
    end
    local host = ngx.var.http_host
    if host == nil then
        host = ngx.var.server_name
    end
    if host == nil then
        ngx.ctx._domain = "default"
        return "default"
    end
    -- strip port: www.example.com:8080 -> www.example.com
    local domain = string.match(host, "^([^:]+)")
    if domain == nil then
        domain = host
    end
    domain = string.lower(domain)
    ngx.ctx._domain = domain
    return domain
end

--Worker-level domain config cache (avoids per-request cjson.decode)
--Stores parsed Lua table + precompiled wildcard regexes
local worker_domain_config = nil      -- parsed domain.json table
local worker_wildcard_patterns = nil  -- precompiled: { {suffix=".example.com", cfg=...}, ... }
local worker_domain_mtime = nil       -- mtime of last loaded domain.json

--Match domain: O(1) exact lookup, then precompiled wildcard suffix match
local function match_domain(domain)
    if worker_domain_config == nil then
        return nil
    end
    -- 1. exact match (hash lookup, O(1))
    local specific = worker_domain_config[domain]
    if specific ~= nil then
        return specific
    end
    -- 2. wildcard match: precompiled suffix strings (no regex per request)
    if worker_wildcard_patterns then
        for _, wc in ipairs(worker_wildcard_patterns) do
            -- wc.suffix = ".example.com", domain ends with it → match
            local suffix = wc.suffix
            local dlen = #domain
            local slen = #suffix
            if dlen > slen and string.sub(domain, dlen - slen + 1) == suffix then
                return wc.cfg
            end
        end
    end
    return nil
end

--Load and parse domain.json into worker memory (called when mtime changes)
--Precompiles wildcard patterns: *.example.com → suffix=".example.com"
local function load_domain_config(filepath, mtime)
    local io = require 'io'
    local f = io.open(filepath, "r")
    if f == nil then
        worker_domain_config = nil
        worker_wildcard_patterns = nil
        worker_domain_mtime = nil
        return
    end
    local content = f:read("*a")
    f:close()

    local cjson = require("cjson")
    local ok, domain_config = pcall(cjson.decode, content)
    if not ok or type(domain_config) ~= "table" then
        worker_domain_config = nil
        worker_wildcard_patterns = nil
        worker_domain_mtime = nil
        return
    end

    -- remove _comment
    domain_config["_comment"] = nil

    -- precompile wildcard patterns: *.example.com → suffix=".example.com"
    local wildcards = {}
    for pattern, cfg in pairs(domain_config) do
        if type(cfg) == "table" and string.find(pattern, "^%*%.") then
            -- *.example.com → .example.com (suffix match, no regex needed)
            local suffix = string.sub(pattern, 2)  -- remove leading *, keep ".example.com"
            table.insert(wildcards, { suffix = suffix, cfg = cfg })
        end
    end

    worker_domain_config = domain_config
    worker_wildcard_patterns = wildcards
    worker_domain_mtime = mtime
end

--Get domain-level config (worker-level Lua table cache, no per-request cjson.decode)
--Reloads only when domain.json mtime changes
--Result is cached per request via ngx.ctx
function get_domain_config()
    if ngx.ctx._domain_config_loaded then
        return ngx.ctx._domain_config
    end
    ngx.ctx._domain_config_loaded = true

    local DOMAIN_FILEPATH = config_rule_dir .. '/domain.json'
    local current_mtime = get_file_mtime(DOMAIN_FILEPATH)

    -- file not found → no domain config, use globals
    if current_mtime == nil then
        ngx.ctx._domain_config = nil
        return nil
    end

    -- check if worker cache is current (mtime comparison, no decode)
    if worker_domain_mtime ~= current_mtime then
        load_domain_config(DOMAIN_FILEPATH, current_mtime)
    end

    -- match domain from worker-level Lua table (O(1) exact + suffix match)
    local result = match_domain(get_domain())
    ngx.ctx._domain_config = result
    return result
end

--Get effective config value: domain-level first, fallback to global config_*
function get_effective_config(key)
    local dcfg = get_domain_config()
    if dcfg and dcfg[key] ~= nil then
        return dcfg[key]
    end
    return _G["config_" .. key]
end

--Worker-level rule cache (avoids per-request cjson.decode)
--key: filepath → { mtime=, rules=Lua table }
local worker_rule_cache = {}

--Read rule lines from a file (cached in worker memory, no per-request cjson.decode)
local function read_rule_file(filepath)
    local current_mtime = get_file_mtime(filepath)
    if current_mtime == nil then
        worker_rule_cache[filepath] = nil
        return nil
    end

    -- check worker-level cache (mtime comparison only, no decode)
    local entry = worker_rule_cache[filepath]
    if entry and entry.mtime == current_mtime then
        return entry.rules
    end

    -- cache miss: read and parse file
    local io = require 'io'
    local f = io.open(filepath, "r")
    if f == nil then
        worker_rule_cache[filepath] = nil
        return nil
    end
    local content = f:read("*a")
    f:close()

    local t = {}
    for line in content:gmatch("[^\r\n]+") do
        table.insert(t, line)
    end
    worker_rule_cache[filepath] = { mtime = current_mtime, rules = t }
    return t
end

--Resolve rule_dir: absolute path used as-is; relative path resolved against config_rule_dir
local function resolve_rule_dir(dir)
    if dir == nil or dir == "" then
        return nil
    end
    -- absolute path starts with "/"
    if string.sub(dir, 1, 1) == "/" then
        return dir
    end
    -- relative path → prepend config_rule_dir
    return config_rule_dir .. '/' .. dir
end

--Get WAF rule (supports per-domain rule_dir override, with caching)
function get_rule(rulefilename)
    local RULE_PATH = config_rule_dir

    -- check domain-level rule_dir
    local dcfg = get_domain_config()
    if dcfg and dcfg["rule_dir"] and dcfg["rule_dir"] ~= "" then
        local resolved = resolve_rule_dir(dcfg["rule_dir"])
        local domain_rules = read_rule_file(resolved .. '/' .. rulefilename)
        if domain_rules ~= nil then
            return domain_rules
        end
    end

    -- fallback to global rule dir
    local rules = read_rule_file(RULE_PATH .. '/' .. rulefilename)
    return rules
end

--WAF log: batch buffer per worker (avoids per-attack open/write/close)
--Buffer flushes every 1 second or when buffer reaches 100 entries
local log_buffer = {}
local log_buffer_count = 0
local LOG_FLUSH_INTERVAL = 100   -- max entries before flush
local log_last_flush_time = 0

--Flush log buffer to file (single open/write/close for batch)
local function flush_log_buffer(log_name)
    if log_buffer_count == 0 then return end
    local lines = table.concat(log_buffer, "\n") .. "\n"
    log_buffer = {}
    log_buffer_count = 0

    -- async via timer
    local ok = pcall(function()
        ngx.timer.at(0, function(premature)
            if premature then return end
            local io = require 'io'
            local file = io.open(log_name, "a")
            if file then
                file:write(lines)
                file:flush()
                file:close()
            end
        end)
    end)
    if not ok then
        local io = require 'io'
        local file = io.open(log_name, "a")
        if file then
            file:write(lines)
            file:flush()
            file:close()
        end
    end
end

function log_record(method,url,data,ruletag)
    local cjson = require("cjson")
    local LOG_PATH = config_log_dir
    local CLIENT_IP = get_client_ip()
    local USER_AGENT = get_user_agent()
    local FORMAT_TIME = os.date("!%Y-%m-%dT%H:%M:%SZ", os.time())
    local LOCAL_TIME = ngx.localtime()
    local DOMAIN = get_domain()
    local log_json_obj = {
                 ['@timestamp'] = FORMAT_TIME,
                 client_ip = CLIENT_IP,
                 local_time = LOCAL_TIME,
                 server_name = DOMAIN,
                 user_agent = USER_AGENT,
                 attack_method = method,
                 req_url = url,
                 req_data = data,
                 rule_tag = ruletag,
              }
    local LOG_LINE = cjson.encode(log_json_obj)
    local LOG_NAME = LOG_PATH..'/'..ngx.today().."_waf.log"

    -- log rotation: check file size only every 60s (not per attack)
    local now = ngx.time()
    if now - log_last_flush_time > 60 then
        log_last_flush_time = now
        local io = require 'io'
        local f_check = io.open(LOG_NAME, "r")
        if f_check then
            local file_size = f_check:seek("end")
            f_check:close()
            if file_size > 104857600 then  -- 100MB
                local os_cmd = require("os")
                os_cmd.rename(LOG_NAME, LOG_NAME .. ".old")
            end
        end
    end

    -- buffer and batch flush
    log_buffer_count = log_buffer_count + 1
    log_buffer[log_buffer_count] = LOG_LINE
    if log_buffer_count >= LOG_FLUSH_INTERVAL then
        flush_log_buffer(LOG_NAME)
    end
end

--WAF return (supports per-domain output config)
function waf_output()
    local output_mode = get_effective_config("waf_output")
    if output_mode == "redirect" then
        ngx.redirect(get_effective_config("waf_redirect_url"), 301)
    else
        ngx.header.content_type = "text/html"
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say(config_output_html)
        ngx.exit(ngx.status)
    end
end
