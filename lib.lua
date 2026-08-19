--waf core lib
require 'config'

--Module-level requires (avoid per-request lookup)
local cjson = require("cjson")
local io = require 'io'
local bit = require("bit")  -- LuaJIT bit module, always available in OpenResty

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

--Validate IPv4 address: returns true if valid dotted-quad
local function is_valid_ipv4(s)
    if s == nil then return false end
    local a, b, c, d = s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return false end
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    return a and b and c and d
        and a >= 0 and a <= 255
        and b >= 0 and b <= 255
        and c >= 0 and c <= 255
        and d >= 0 and d <= 255
end

--Validate IPv6 address: basic check for hex groups separated by colons
local function is_valid_ipv6(s)
    if s == nil then return false end
    -- must contain at least one colon, only hex digits and colons
    if not s:find(":") then return false end
    if s:match("[^%x:]") then return false end
    -- check length: max 39 chars (8 groups of 4 hex + 7 colons)
    if #s > 39 then return false end
    -- check groups: split by colon
    local groups = {}
    for g in s:gmatch("([^:]+)") do
        if #g > 4 then return false end
        table.insert(groups, g)
    end
    -- must have at least 3 groups (shortest: ::1)
    if #groups < 2 and s:find("::") then return false end
    if #groups < 3 and not s:find("::") then return false end
    return true
end

--Forward declaration: is_cdn_ip is defined later (after get_rule_entry) but
--get_client_ip (defined above) references it at runtime. This ensures the local binding.
local is_cdn_ip

--Validate IP address (IPv4 or IPv6)
local function is_valid_ip(s)
    if s == nil or type(s) ~= "string" then return false end
    return is_valid_ipv4(s) or is_valid_ipv6(s)
end

--Convert IPv4 dotted-quad to 32-bit number (returns nil on invalid)
--Returns signed 32-bit (LuaJIT bit ops use signed 32-bit), so bit.tobit() ensures
--all IPv4 numbers are in the same numeric domain for comparisons
local function ipv4_to_num(s)
    local a, b, c, d = s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    if not (a and b and c and d) then return nil end
    if a > 255 or b > 255 or c > 255 or d > 255 then return nil end
    return bit.tobit(a * 16777216 + b * 65536 + c * 256 + d)
end

--Binary search: find if ip_num falls within any range in sorted list
--ranges: sorted array of {lo=, hi=} ascending by lo
local function binary_search_range(ranges, target)
    local lo_idx, hi_idx = 1, #ranges
    while lo_idx <= hi_idx do
        local mid = bit.rshift(lo_idx + hi_idx, 1)
        local r = ranges[mid]
        if target < r.lo then
            hi_idx = mid - 1
        elseif target > r.hi then
            lo_idx = mid + 1
        else
            return true
        end
    end
    return false
end

--Expand IPv6 to 8 full hex groups (e.g. "2001:db8::1" → {"2001","0db8","0000",...,"0001"})
--Returns array of 8 strings (each 1-4 hex digits), or nil on invalid
local function ipv6_expand(s)
    if s == nil or type(s) ~= "string" then return nil end
    if not s:find(":") or s:match("[^%x:]") then return nil end
    if #s > 39 then return nil end

    local function split_colon(str)
        local parts = {}
        for p in str:gmatch("([^:]+)") do table.insert(parts, p) end
        return parts
    end

    local groups
    if s:find("::") then
        local left_str, right_str = s:match("^(.-)::(.*)$")
        if left_str == nil then return nil end
        -- check for multiple ::
        if right_str and right_str:find("::") then return nil end
        local left_parts, right_parts = {}, {}
        if left_str and left_str ~= "" then left_parts = split_colon(left_str) end
        if right_str and right_str ~= "" then right_parts = split_colon(right_str) end
        local total = #left_parts + #right_parts
        if total > 7 then return nil end
        local zeros = 8 - total
        groups = {}
        for _, p in ipairs(left_parts) do table.insert(groups, p) end
        for _ = 1, zeros do table.insert(groups, "0") end
        for _, p in ipairs(right_parts) do table.insert(groups, p) end
    else
        groups = split_colon(s)
    end

    if #groups ~= 8 then return nil end
    for i, g in ipairs(groups) do
        if #g > 4 or tonumber(g, 16) == nil then return nil end
    end
    return groups
end

--Convert IPv6 to 4 x 32-bit numbers (each fits in LuaJIT 32-bit bit ops)
--groups 1-2 → chunk0, groups 3-4 → chunk1, groups 5-6 → chunk2, groups 7-8 → chunk3
--Returns (c0, c1, c2, c3) or nil on invalid
--bit.tobit() ensures values are signed 32-bit, same domain as bit.band() results
local function ipv6_to_chunks(s)
    local g = ipv6_expand(s)
    if g == nil then return nil end
    local c0 = bit.tobit(tonumber(g[1], 16) * 65536 + tonumber(g[2], 16))
    local c1 = bit.tobit(tonumber(g[3], 16) * 65536 + tonumber(g[4], 16))
    local c2 = bit.tobit(tonumber(g[5], 16) * 65536 + tonumber(g[6], 16))
    local c3 = bit.tobit(tonumber(g[7], 16) * 65536 + tonumber(g[8], 16))
    return c0, c1, c2, c3
end
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
    -- Choose wildcard replacement based on IP type:
    -- IPv4 pattern (contains . but no :) → \d+ (digits only, prevents matching IPv6)
    -- IPv6 pattern (contains :) → [\da-fA-F:]+ (hex digits + colons)
    if string.find(pattern, ":") then
        regex = string.gsub(regex, "%*", "[\\da-fA-F:]+")
    else
        regex = string.gsub(regex, "%*", "[\\d]+")
    end
    -- anchor full match
    return "^" .. regex .. "$"
end

--Get the client IP
--When trust_proxy_headers="on": extract from X-Forwarded-For/X-Real-IP/CF-Connecting-IP
--  - cdnip.rule exists  = only trust XFF when remote_addr is from a CDN IP (secure)
--  - cdnip.rule absent  = trust XFF from any source (original behavior)
--When trust_proxy_headers="off": only use remote_addr (prevent IP spoofing)
--Supports per-domain override via domain.json
function get_client_ip()
    if ngx.ctx._client_ip then
        return ngx.ctx._client_ip
    end
    local ip
    if get_effective_config("trust_proxy_headers") ~= "off" then
        -- Security check: only trust forwarded headers if the direct connection
        -- comes from a trusted CDN/proxy IP (prevents direct XFF spoofing)
        -- is_cdn_ip returns nil when cdnip.rule doesn't exist (= trust all, original behavior)
        -- is_cdn_ip returns false when remote_addr is not in cdnip.rule (= do NOT trust XFF)
        local remote = ngx.var.remote_addr
        if is_cdn_ip(remote) ~= false then
            local headers = ngx.req.get_headers()
            -- 1. CF-Connecting-IP (Cloudflare specific, most reliable)
            ip = headers["CF_Connecting_IP"] or headers["cf-connecting-ip"]
            if ip ~= nil and not is_valid_ip(ip) then ip = nil end
            -- 2. X-Real-IP
            if ip == nil then
                ip = headers["X_real_ip"] or headers["X-Real-IP"]
                if ip ~= nil and not is_valid_ip(ip) then ip = nil end
            end
            -- 3. X-Forwarded-For (take first valid IP if multiple)
            if ip == nil then
                local xff = headers["X_Forwarded_For"] or headers["X-Forwarded-For"]
                if xff then
                    -- extract first valid IP: "103.119.132.48, 162.158.179.193" -> "103.119.132.48"
                    -- strictly validate IP format to prevent spoofing with fake hostnames
                    for entry in xff:gmatch("([^,]+)") do
                        local candidate = entry:match("^%s*(%S+)%s*$")
                        if candidate and is_valid_ip(candidate) then
                            ip = candidate
                            break
                        end
                    end
                end
            end
        end
    end
    -- 4. remote_addr (always available, or fallback when headers not trusted or not from CDN)
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
    -- Skip for cdnip.rule: CIDR entries are pre-compiled by load_cdnip_cache,
    -- building a combined regex from CIDR strings (e.g. 1.180.27.0/24) is useless and wasteful
    local is_cdnip = filepath:match("cdnip%.rule$")
    local parts = {}
    -- Dual-engine: separate plain-string rules (fast: string.find) from regex rules
    -- Plain rules have NO regex metacharacters: ( ) [ ] { } . * + ? ^ $ | \
    -- These can be matched with string.find (plain mode) which is ~10x faster than regex
    local fast_rules = {}
    local regex_rules = {}
    if not is_cdnip then
        for _, r in ipairs(t) do
            if r ~= "" then
                -- Check if rule contains regex metacharacters
                if r:find("[()%.%[%]%*%+%?%^%$|\\]") then
                    table.insert(regex_rules, r)
                else
                    table.insert(fast_rules, r)
                end
                table.insert(parts, r)
            end
        end
    end
    local combined = nil
    if #regex_rules > 0 then
        combined = "(?:" .. table.concat(regex_rules, "|") .. ")"
    end

    -- Pre-compile glob patterns (for IP rules like 192.168.*)
    -- Skip for cdnip.rule: handled by load_cdnip_cache
    local glob_compiled = {}
    if not is_cdnip then
        for _, r in ipairs(t) do
            if r ~= "" and string.find(r, "%*") then
                table.insert(glob_compiled, glob_to_regex(r))
            end
        end
    end

    worker_rule_cache[filepath] = {
        mtime = current_mtime, rules = t, combined = combined,
        fast_rules = fast_rules, glob_compiled = glob_compiled, last_check = now
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

--===========================================================================
--Unified IP rule matching: CIDR + wildcard + exact IP for all *.rule files
--Used by blackip.rule, whiteip.rule, cdnip.rule — all support same formats
--===========================================================================

--Worker-level cache for compiled IP rules
--key: filepath → { ipv4_ranges=, ipv6_list=, glob_list=, exact_list=, mtime= }
local worker_ip_cache = {}

--Compile IP rule lines into pre-compiled CIDR ranges, glob regexes, exact IPs
--Skips comment lines (#) and empty lines
--Returns: { ipv4_ranges=sorted, ipv6_list=, glob_list=, exact_list= }
local function compile_ip_rules(rules)
    local ipv4_ranges = {}
    local ipv6_list = {}
    local glob_list = {}
    local exact_list = {}

    for _, line in ipairs(rules) do
        if line ~= "" and not line:match("^#") then
            if line:find("/") then
                -- CIDR notation (IPv4 or IPv6)
                local cidr_ip, prefix_str = line:match("^([%d%.:%x]+)/(%d+)$")
                if cidr_ip and prefix_str then
                    local prefix = tonumber(prefix_str)
                    if cidr_ip:find(":") then
                        -- IPv6 CIDR
                        local c0, c1, c2, c3 = ipv6_to_chunks(cidr_ip)
                        if c0 and prefix <= 128 then
                            local m0, m1, m2, m3 = 0, 0, 0, 0
                            if prefix >= 32 then
                                m0 = 0xFFFFFFFF
                                if prefix >= 64 then
                                    m1 = 0xFFFFFFFF
                                    if prefix >= 96 then
                                        m2 = 0xFFFFFFFF
                                        if prefix == 128 then
                                            m3 = 0xFFFFFFFF
                                        elseif prefix > 96 then
                                            m3 = bit.lshift(0xFFFFFFFF, 128 - prefix)
                                        end
                                    elseif prefix > 64 then
                                        m2 = bit.lshift(0xFFFFFFFF, 96 - prefix)
                                    end
                                elseif prefix > 32 then
                                    m1 = bit.lshift(0xFFFFFFFF, 64 - prefix)
                                end
                            elseif prefix > 0 then
                                m0 = bit.lshift(0xFFFFFFFF, 32 - prefix)
                            end
                            table.insert(ipv6_list, {
                                c0 = bit.band(c0, m0), c1 = bit.band(c1, m1),
                                c2 = bit.band(c2, m2), c3 = bit.band(c3, m3),
                                m0 = m0, m1 = m1, m2 = m2, m3 = m3
                            })
                        end
                    else
                        -- IPv4 CIDR
                        local base = ipv4_to_num(cidr_ip)
                        if base and prefix <= 32 then
                            local mask
                            if prefix == 0 then
                                mask = 0
                            elseif prefix == 32 then
                                mask = 0xFFFFFFFF
                            else
                                mask = bit.lshift(0xFFFFFFFF, 32 - prefix)
                            end
                            local range_lo = bit.band(base, mask)
                            local range_hi = bit.bor(range_lo, bit.bnot(mask))
                            range_hi = bit.band(range_hi, 0xFFFFFFFF)
                            table.insert(ipv4_ranges, {lo = range_lo, hi = range_hi})
                        end
                    end
                end
            elseif line:find("%*") then
                -- Wildcard pattern (e.g. 192.168.*)
                table.insert(glob_list, glob_to_regex(line))
            else
                -- Exact IP (normalize to lowercase for case-insensitive IPv6 matching)
                table.insert(exact_list, string.lower(line))
            end
        end
    end

    -- Sort IPv4 ranges by lo for binary search
    table.sort(ipv4_ranges, function(a, b) return a.lo < b.lo end)

    return {
        ipv4_ranges = ipv4_ranges,
        ipv6_list = ipv6_list,
        glob_list = glob_list,
        exact_list = exact_list,
    }
end

--Get compiled IP rule cache for a rule file (TTL-based, recompiles on mtime change)
--Returns compiled table or nil if file doesn't exist
local function get_compiled_ip_rules(rulefilename)
    local entry = get_rule_entry(rulefilename)
    if entry == nil then return nil end

    local cache = worker_ip_cache[rulefilename]
    if cache and cache.mtime == entry.mtime then
        return cache
    end

    -- recompile
    local compiled = compile_ip_rules(entry.rules)
    compiled.mtime = entry.mtime
    worker_ip_cache[rulefilename] = compiled
    return compiled
end

--Match an IP against compiled IP rules (CIDR + wildcard + exact)
--Returns true if match, false if no match, nil if rule file doesn't exist
local function match_compiled_ip(compiled, ip)
    if compiled == nil or ip == nil then return nil end
    local ip_lower = string.lower(ip)

    -- IPv4: binary search on pre-compiled sorted ranges
    if is_valid_ipv4(ip) then
        local num = ipv4_to_num(ip)
        if num and binary_search_range(compiled.ipv4_ranges, num) then
            return true
        end
    elseif is_valid_ipv6(ip) then
        -- IPv6: check against all pre-compiled CIDR entries
        local c0, c1, c2, c3 = ipv6_to_chunks(ip)
        if c0 then
            for _, r in ipairs(compiled.ipv6_list) do
                if bit.band(c0, r.m0) == r.c0 and bit.band(c1, r.m1) == r.c1
                   and bit.band(c2, r.m2) == r.c2 and bit.band(c3, r.m3) == r.c3 then
                    return true
                end
            end
        end
    end

    -- Check glob patterns (wildcards like 192.168.*)
    for _, gregex in ipairs(compiled.glob_list) do
        if rulematch(ip, gregex, "jo") then
            return true
        end
    end

    -- Check exact IPs (case-insensitive via lowercase normalization)
    for _, ex in ipairs(compiled.exact_list) do
        if ip_lower == ex then
            return true
        end
    end

    return false
end

--Match IP against a rule file (supports CIDR, wildcards, exact IPs, comments)
--Returns true if IP matches, nil if rule file doesn't exist or no match
function match_ip_rule(rulefilename, ip)
    local compiled = get_compiled_ip_rules(rulefilename)
    if compiled == nil then return nil end
    return match_compiled_ip(compiled, ip) or nil
end

--===========================================================================
--Unified IP rule matching: CIDR + wildcard + exact IP for all *.rule files
--Returns: true  = IP is in CDN list (trust XFF)
--         false = IP is NOT in CDN list (do NOT trust XFF)
--         nil   = cdnip.rule doesn't exist (trust XFF from any source, original behavior)
is_cdn_ip = function(ip)
    if ip == nil then return nil end
    local compiled = get_compiled_ip_rules("cdnip.rule")
    if compiled == nil then
        return nil  -- cdnip.rule doesn't exist = trust all (original behavior)
    end
    return match_compiled_ip(compiled, ip)
end

--Get NginxGuard rule (returns rules array only, for backward compat)
function get_rule(rulefilename)
    local entry = get_rule_entry(rulefilename)
    if entry == nil then return nil end
    return entry.rules
end

--Fast match: check if input matches ANY rule in a rule file
--Returns the matched rule string (for logging), or nil if no match
--Dual-engine: fast string.find for plain rules + combined regex for regex rules
function match_any_rule(rulefilename, input, flags)
    local entry = get_rule_entry(rulefilename)
    if entry == nil then return nil end

    -- Engine 1: Fast plain-string matching (string.find, ~10x faster than regex)
    -- Only runs if the rule file has plain-string rules
    if entry.fast_rules and #entry.fast_rules > 0 then
        for _, rule in ipairs(entry.fast_rules) do
            if string.find(input, rule, 1, true) then
                return rule
            end
        end
    end

    -- Engine 2: Combined regex matching (ngx.re.find)
    -- Only runs if the rule file has regex rules
    if entry.combined ~= nil then
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

    -- Fallback: per-rule matching (when combined is nil or errored)
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
    -- use shared dict as cross-worker lock to prevent concurrent rotation
    local now = ngx.time()
    if now - log_last_rotation_time > 60 then
        log_last_rotation_time = now
        -- acquire cross-worker lock via shared dict (TTL=10s to prevent stale lock)
        local waf_lock = ngx.shared.badGuys
        local lock_key = "log_rotation_lock"
        local acquired = false
        if waf_lock then
            local res, err = waf_lock:add(lock_key, 1, 10)
            if res then
                acquired = true
            end
        else
            acquired = true  -- no shared dict, proceed without lock
        end
        if acquired then
            local f_check = io.open(LOG_NAME, "r")
            if f_check then
                local file_size = f_check:seek("end")
                f_check:close()
                if file_size > 104857600 then  -- 100MB
                    os.rename(LOG_NAME, LOG_NAME .. ".old")
                end
            end
            if waf_lock then
                waf_lock:delete(lock_key)
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
