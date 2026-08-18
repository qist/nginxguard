--waf core lib
require 'config'

--Module-level requires (avoid per-request lookup)
local cjson = require("cjson")
local io = require 'io'

--Cache via ngx.shared.dict, fallback to direct read if not configured
local rulematch = ngx.re.find

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
--IPv4: 192.168.0.* → ^192\.168\.0\.\d+$
--IPv4: 192.168.*.1  → ^192\.168\.\d+\.1$
--IPv6: 2001:db8::*  → ^2001\:db8\::[\da-fA-F:]+$
--IPv6: 2001:*:1     → ^2001\:[\da-fA-F:]+\:1$
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
    -- replace * with [\da-fA-F:]+ to match both IPv4 (digits) and IPv6 (hex + colon)
    regex = string.gsub(regex, "%*", "[\\da-fA-F:]+")
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
    local USER_AGENT = ngx.var.http_user_agent
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

--Rule cache TTL: re-check file mtime at most every N seconds (not per-request)
--This eliminates ~10 stat() syscalls per request → ~0 (amortized)
local RULE_CACHE_TTL = 10  -- seconds between mtime re-checks

--Worker-level domain config cache (avoids per-request cjson.decode)
--Stores parsed Lua table + precompiled wildcard regexes
local worker_domain_config = nil      -- parsed domain.json table
local worker_wildcard_patterns = nil  -- precompiled: { {suffix=".example.com", cfg=...}, ... }
local worker_domain_mtime = nil       -- mtime of last loaded domain.json
local worker_domain_last_check = 0    -- last time we stat()'d domain.json (ngx.time)

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
    local f = io.open(filepath, "r")
    if f == nil then
        worker_domain_config = nil
        worker_wildcard_patterns = nil
        worker_domain_mtime = nil
        return
    end
    local content = f:read("*a")
    f:close()

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

    -- TTL-based mtime check: only stat() once every RULE_CACHE_TTL seconds
    local now = ngx.time()
    if now - worker_domain_last_check >= RULE_CACHE_TTL then
        worker_domain_last_check = now
        local DOMAIN_FILEPATH = config_rule_dir .. '/domain.json'
        local current_mtime = get_file_mtime(DOMAIN_FILEPATH)

        if current_mtime == nil then
            -- file removed: clear cache
            if worker_domain_config ~= nil then
                worker_domain_config = nil
                worker_wildcard_patterns = nil
                worker_domain_mtime = nil
            end
            ngx.ctx._domain_config = nil
            return nil
        end

        -- reload only if mtime changed
        if worker_domain_mtime ~= current_mtime then
            load_domain_config(DOMAIN_FILEPATH, current_mtime)
        end
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

--Worker-level rule cache (avoids per-request cjson.decode AND per-request stat())
--key: filepath → { mtime=, rules=Lua table, last_check=timestamp }
local worker_rule_cache = {}

--Read rule lines from a file (cached in worker memory with TTL-based invalidation)
local function read_rule_file(filepath)
    local entry = worker_rule_cache[filepath]
    local now = ngx.time()

    -- Fast path: cache hit and within TTL window → return immediately (NO stat())
    if entry and (now - entry.last_check) < RULE_CACHE_TTL then
        return entry.rules
    end

    -- TTL expired: re-stat to check if file changed
    local current_mtime = get_file_mtime(filepath)
    if current_mtime == nil then
        worker_rule_cache[filepath] = nil
        return nil
    end

    -- mtime unchanged → just update last_check, return cached rules
    if entry and entry.mtime == current_mtime then
        entry.last_check = now
        return entry.rules
    end

    -- cache miss or file changed: read and parse file
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

    -- Build combined alternation pattern for fast matching
    -- (?:rule1|rule2|rule3|...) — 1 regex match instead of N
    local parts = {}
    for _, r in ipairs(t) do
        if r ~= "" then
            table.insert(parts, r)
        end
    end
    local combined = nil
    if #parts > 0 then
        combined = "(?:" .. table.concat(parts, "|") .. ")"
    end

    -- Pre-compile glob patterns (for IP rules like 192.168.*)
    -- Store compiled regexes so we don't call glob_to_regex per request
    local glob_compiled = {}
    for _, r in ipairs(t) do
        if r ~= "" and string.find(r, "%*") then
            table.insert(glob_compiled, glob_to_regex(r))
        end
    end

    worker_rule_cache[filepath] = {
        mtime = current_mtime, rules = t, combined = combined,
        glob_compiled = glob_compiled, last_check = now
    }
    return t
end

--Resolve rule_dir: absolute path used as-is; relative path resolved against config_rule_dir
--Must be defined BEFORE get_rule_entry (Lua local scope requirement)
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

--Get full rule entry (rules array + combined pattern) for a rule file
--Supports per-domain rule_dir override, with TTL caching
function get_rule_entry(rulefilename)
    local RULE_PATH = config_rule_dir
    local dcfg = get_domain_config()
    if dcfg and dcfg["rule_dir"] and dcfg["rule_dir"] ~= "" then
        local resolved = resolve_rule_dir(dcfg["rule_dir"])
        if resolved then
            local domain_filepath = resolved .. '/' .. rulefilename
            local domain_entry = worker_rule_cache[domain_filepath]
            if domain_entry and (ngx.time() - domain_entry.last_check) < RULE_CACHE_TTL then
                return domain_entry
            end
            -- try to read from domain-specific rule dir
            local domain_rules = read_rule_file(domain_filepath)
            if domain_rules ~= nil then
                return worker_rule_cache[domain_filepath]
            end
            -- domain rule file doesn't exist → fall through to global rules
        end
    end
    local filepath = RULE_PATH .. '/' .. rulefilename
    local entry = worker_rule_cache[filepath]
    local now = ngx.time()
    if entry and (now - entry.last_check) < RULE_CACHE_TTL then
        return entry
    end
    read_rule_file(filepath)
    return worker_rule_cache[filepath]
end

--Match IP against a rule file (uses pre-compiled glob patterns)
--Returns true if IP matches any rule, nil otherwise
function match_ip_rule(rulefilename, ip)
    local entry = get_rule_entry(rulefilename)
    if entry == nil then return nil end
    -- Check pre-compiled glob patterns (wildcard IPs like 192.168.*)
    if entry.glob_compiled then
        for _, gregex in ipairs(entry.glob_compiled) do
            if rulematch(ip, gregex, "jo") then
                return true
            end
        end
    end
    -- Check non-glob rules (exact IPs like 8.8.8.8, or regex)
    for _, rule in ipairs(entry.rules) do
        if rule ~= "" and not string.find(rule, "%*") then
            if rulematch(ip, rule, "jo") then
                return true
            end
        end
    end
    return nil
end

--Get NginxGuard rule (returns rules array only, for backward compat)
function get_rule(rulefilename)
    local entry = get_rule_entry(rulefilename)
    if entry == nil then return nil end
    return entry.rules
end

--Fast match: check if input matches ANY rule in a rule file
--Returns the matched rule string (for logging), or nil if no match
--Uses combined alternation pattern for O(1) regex match on normal traffic
function match_any_rule(rulefilename, input, flags)
    local entry = get_rule_entry(rulefilename)
    if entry == nil then return nil end
    -- Fast path: single combined regex match (covers 99%+ of normal traffic)
    if entry.combined ~= nil then
        -- Use multi-return form to detect regex compile errors.
        -- ngx.re.find returns (from, to, err); on compile error from=nil and err is set.
        -- A compile error must NOT be treated as "no match" (fail-open); fall back to
        -- per-rule matching so a single bad rule does not silently disable the whole file.
        local from, _, err = rulematch(input, entry.combined, flags)
        if err then
            ngx.log(ngx.ERR, "[NginxGuard] rule file '", rulefilename,
                    "' combined regex compile/exec error: ", err,
                    " — falling back to per-rule matching")
        elseif from then
            -- Slow path (attack detected): find which specific rule matched for logging
            for _, rule in ipairs(entry.rules) do
                if rule ~= "" and rulematch(input, rule, flags) then
                    return rule
                end
            end
            return ""  -- combined matched but individual didn't (edge case)
        else
            return nil  -- genuine no-match, fast path clean
        end
    end
    -- Fallback: per-rule matching (also used when combined is nil or errored above)
    for _, rule in ipairs(entry.rules) do
        if rule ~= "" and rulematch(input, rule, flags) then
            return rule
        end
    end
    return nil
end

--NginxGuard log: synchronous write (attack logs must not be lost)
--Only triggered on attack detection, normal traffic has zero log overhead
local log_last_rotation_time = 0

function log_record(method,url,data,ruletag)
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
    if now - log_last_rotation_time > 60 then
        log_last_rotation_time = now
        local f_check = io.open(LOG_NAME, "r")
        if f_check then
            local file_size = f_check:seek("end")
            f_check:close()
            if file_size > 104857600 then  -- 100MB
                os.rename(LOG_NAME, LOG_NAME .. ".old")
            end
        end
    end

    -- Synchronous write: ensures log is on disk before ngx.exit(403)
    local file = io.open(LOG_NAME, "a")
    if file then
        file:write(LOG_LINE .. "\n")
        file:flush()
        file:close()
    end
end

--No-op, kept for backward compat (logs are now written synchronously)
function flush_waf_logs()
end

--NginxGuard return (supports per-domain output config)
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
