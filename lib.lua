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

--Match domain in domain_config table (exact + wildcard)
local function match_domain(domain_config, domain)
    -- exact match
    local specific = domain_config[domain]
    if specific ~= nil then
        return specific
    end
    -- wildcard match: *.example.com
    for pattern, cfg in pairs(domain_config) do
        if pattern ~= "_comment" and type(cfg) == "table" then
            if string.find(pattern, "^%*%.") then
                -- convert *.example.com -> ^.+\.example\.com$ (PCRE regex)
                local regex = string.gsub(pattern, "%.", "\\.")
                regex = string.gsub(regex, "^%*\\%.", "^.+\\.")
                regex = regex .. "$"
                if ngx.re.find(domain, regex, "ijo") then
                    return cfg
                end
            end
        end
    end
    return nil
end

--Get domain-level config (cached in shared dict, reloads when domain.json changes)
--Result is also cached per request via ngx.ctx
function get_domain_config()
    if ngx.ctx._domain_config_loaded then
        return ngx.ctx._domain_config
    end
    ngx.ctx._domain_config_loaded = true

    local RULE_PATH = config_rule_dir
    local DOMAIN_FILEPATH = RULE_PATH .. '/domain.json'

    -- get file mtime (real mtime via lfs, or file size as fallback)
    local current_mtime = get_file_mtime(DOMAIN_FILEPATH)

    -- file not found → no domain config, use globals
    if current_mtime == nil then
        ngx.ctx._domain_config = nil
        return nil
    end

    -- check shared dict cache
    if waf_cache then
        local cached_mtime = waf_cache:get("domain_json_mtime")
        local cached_data = waf_cache:get("domain_json_data")
        if cached_mtime == current_mtime and cached_data ~= nil then
            local cjson = require("cjson")
            local ok, domain_config = pcall(cjson.decode, cached_data)
            if ok and type(domain_config) == "table" then
                local result = match_domain(domain_config, get_domain())
                ngx.ctx._domain_config = result
                return result
            end
        end
    end

    -- read and parse file
    local io = require 'io'
    local f = io.open(DOMAIN_FILEPATH, "r")
    if f == nil then
        ngx.ctx._domain_config = nil
        return nil
    end
    local content = f:read("*a")
    f:close()

    local cjson = require("cjson")
    local ok, domain_config = pcall(cjson.decode, content)
    if not ok or type(domain_config) ~= "table" then
        ngx.ctx._domain_config = nil
        return nil
    end

    -- update cache (with TTL for file-size fallback mode)
    if waf_cache then
        waf_cache:set("domain_json_mtime", current_mtime, cache_ttl)
        waf_cache:set("domain_json_data", content, cache_ttl)
    end

    local result = match_domain(domain_config, get_domain())
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

--Read rule lines from a file, return table (cached in shared dict)
local function read_rule_file(filepath)
    -- get file mtime (real mtime via lfs, or file size as fallback)
    local current_mtime = get_file_mtime(filepath)
    if current_mtime == nil then
        return nil
    end

    -- check shared dict cache
    if waf_cache then
        local cache_key = "rule:" .. filepath
        local cached_mtime = waf_cache:get(cache_key .. "_mtime")
        local cached_data = waf_cache:get(cache_key .. "_data")
        if cached_mtime == current_mtime and cached_data ~= nil then
            local cjson = require("cjson")
            local ok, rules = pcall(cjson.decode, cached_data)
            if ok and type(rules) == "table" then
                return rules
            end
        end

        -- cache miss: read and parse file
        local io = require 'io'
        local f = io.open(filepath, "r")
        if f == nil then
            return nil
        end
        local content = f:read("*a")
        f:close()

        local cjson = require("cjson")
        local t = {}
        for line in content:gmatch("[^\r\n]+") do
            table.insert(t, line)
        end
        -- update cache (with TTL for file-size fallback mode)
        waf_cache:set(cache_key .. "_mtime", current_mtime, cache_ttl)
        waf_cache:set(cache_key .. "_data", cjson.encode(t), cache_ttl)
        return t
    end

    -- no cache: parse directly
    local io = require 'io'
    local f = io.open(filepath, "r")
    if f == nil then
        return nil
    end
    local content = f:read("*a")
    f:close()

    local t = {}
    for line in content:gmatch("[^\r\n]+") do
        table.insert(t, line)
    end
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

--WAF log record for json,(use logstash codec => json)
--Uses ngx.timer.at for async file write to avoid blocking worker
--Falls back to sync write if timer API unavailable
local function async_write_log(log_name, log_line)
    -- try async via timer
    local ok = pcall(function()
        ngx.timer.at(0, function(premature)
            if premature then return end
            local io = require 'io'
            local file = io.open(log_name, "a")
            if file then
                file:write(log_line .. "\n")
                file:flush()
                file:close()
            end
        end)
    end)
    if not ok then
        -- fallback: sync write
        local io = require 'io'
        local file = io.open(log_name, "a")
        if file then
            file:write(log_line .. "\n")
            file:flush()
            file:close()
        end
    end
end

function log_record(method,url,data,ruletag)
    local cjson = require("cjson")
    local io = require 'io'
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

    -- log rotation: if file > 100MB, rename to .old
    local file_size = 0
    local f_check = io.open(LOG_NAME, "r")
    if f_check then
        file_size = f_check:seek("end")
        f_check:close()
    end
    if file_size > 104857600 then  -- 100MB
        local os_cmd = require("os")
        os_cmd.rename(LOG_NAME, LOG_NAME .. ".old")
    end

    async_write_log(LOG_NAME, LOG_LINE)
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
