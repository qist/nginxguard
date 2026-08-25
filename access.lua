--NginxGuard Action
require 'config'
require 'lib'

--args
local rulematch = ngx.re.find
local unescape = ngx.unescape_uri
local io = require 'io'
local string_find = string.find
local req_get_method = ngx.req.get_method
local req_get_uri_args = ngx.req.get_uri_args
local req_get_post_args = ngx.req.get_post_args
local req_read_body = ngx.req.read_body
local req_get_body_data = ngx.req.get_body_data
local req_get_body_file = ngx.req.get_body_file
local var = ngx.var
local shared = ngx.shared
local re_gmatch = ngx.re.gmatch
local re_gsub = ngx.re.gsub
local pcall = pcall
local tonumber = tonumber
local tostring = tostring
local type = type
local pairs = pairs
local ipairs = ipairs
local table_insert = table.insert
local table_concat = table.concat

--Safe table concat: filters out non-string/non-number values (e.g. boolean true
--from ngx.req.get_uri_args for flags like ?name without =value)
--before concatenating, preventing "invalid value (boolean)" errors
local function safe_table_concat(t, sep)
    local parts = {}
    for _, v in ipairs(t) do
        local tv = type(v)
        if tv == "string" then
            table_insert(parts, v)
        elseif tv == "number" then
            table_insert(parts, tostring(v))
        end
    end
    if #parts == 0 then return nil end
    return table_concat(parts, sep)
end
local string_sub = string.sub
local string_char = string.char
local string_lower = string.lower
local string_gsub = string.gsub

local MAX_URI_ARGS_PARSE = 256
local MAX_INSPECTABLE_BODY_FILE_SIZE = 2097152
local DEFAULT_UPLOAD_FILENAME_SCAN_LIMIT = 0

--Combined decode: recursive URL-decode + JS unicode/entity decode in one pass
--FAST PATH: only runs decoders if their markers are present
--Normal traffic (no % \u \x &#) costs ZERO regex/decode overhead
--Returns: decoded_string, was_changed (true if any decoding happened)
local function full_decode(s)
    if s == nil then return s, false end
    local changed = false
    -- Step 1: recursive URL-decode (only if '%' present)
    if string_find(s, "%", 1, true) then
        local prev = s
        for _ = 1, 8 do
            local decoded = unescape(prev)
            if decoded == prev then break end
            prev = decoded
            changed = true
        end
        s = prev
    end
    -- Step 2: JS unicode/hex/entity decode (only if markers present)
    local has_js = false
    if string_find(s, "\\u", 1, true) then has_js = true
    elseif string_find(s, "\\x", 1, true) then has_js = true
    elseif string_find(s, "&#", 1, true) then has_js = true
    end
    if has_js then
        local before = s
        s = re_gsub(s, [[\\u\{([0-9a-fA-F]{1,6})\}]], function(m)
            local code = tonumber(m[1], 16)
            if code and code >= 32 and code <= 126 then return string_char(code) end
            return m[0]
        end, "jo")
        s = re_gsub(s, [[\\u([0-9a-fA-F]{4})]], function(m)
            local code = tonumber(m[1], 16)
            if code and code >= 32 and code <= 126 then return string_char(code) end
            return m[0]
        end, "jo")
        s = re_gsub(s, [[\\x([0-9a-fA-F]{2})]], function(m)
            local code = tonumber(m[1], 16)
            if code and code >= 32 and code <= 126 then return string_char(code) end
            return m[0]
        end, "jo")
        s = re_gsub(s, [[&#x([0-9a-fA-F]{2,4});]], function(m)
            local code = tonumber(m[1], 16)
            if code and code >= 32 and code <= 126 then return string_char(code) end
            return m[0]
        end, "joi")
        s = re_gsub(s, [[&#(\d{2,3});]], function(m)
            local code = tonumber(m[1])
            if code and code >= 32 and code <= 126 then return string_char(code) end
            return m[0]
        end, "joi")
        if s ~= before then changed = true end
    end
    return s, changed
end

--Quick check: does string contain any encoding markers?
local function has_encode_markers(s)
    if s == nil then return false end
    return string_find(s, "%", 1, true) ~= nil
        or string_find(s, "\\u", 1, true) ~= nil
        or string_find(s, "\\x", 1, true) ~= nil
        or string_find(s, "&#", 1, true) ~= nil
end

--=========================================================================
-- OPTIMIZATION 3: Cache all config lookups to ngx.ctx per-request
-- Instead of calling get_effective_config() ~13 times per request,
-- load all config keys once into ngx.ctx._cfg and read from there.
--=========================================================================
local CONFIG_KEYS = {
    "waf_enable", "white_ip_check", "black_ip_check", "white_url_check",
    "white_ua_check", "user_agent_check", "url_check", "url_args_check",
    "cookie_check", "cc_check", "cc_rate", "cc_block_ttl",
    "post_check", "referer_check", "file_upload_check", "trust_proxy_headers",
    "multipart_streaming_check", "upload_filename_scan_limit", "post_body_scan_limit",
    "bodyless",
}

local function cfg(key)
    local ctx = ngx.ctx
    if ctx._cfg == nil then
        ctx._cfg = {}
        for _, k in ipairs(CONFIG_KEYS) do
            ctx._cfg[k] = get_effective_config(k)
        end
    end
    return ctx._cfg[key]
end

local function is_waf_enabled()
    return cfg("waf_enable")
end

-- OPTIMIZATION: combined check for waf_enable + a feature flag in one call
-- Avoids separate is_waf_enabled() calls inside each check function
local function waf_on_and(key)
    return cfg("waf_enable") == "on" and cfg(key) == "on"
end

-- Whether the given method is treated as "bodyless" (no request body to scan).
-- Controlled by config_bodyless:
--   "on"  (default) -> GET/HEAD/OPTIONS skip body/post/file_upload checks
--   "off"           -> every method is scanned for body/post content
local function is_bodyless_method(method)
    if cfg("bodyless") == "off" then
        return false
    end
    return method == "GET" or method == "HEAD" or method == "OPTIONS"
end

local function is_multipart_streaming_enabled()
    return cfg("multipart_streaming_check") == "on"
end

local function cfg_number(key, default_value)
    local value = tonumber(cfg(key))
    if value == nil then
        return default_value
    end
    return value
end

--allow white ip
local function white_ip_check()
     if cfg("white_ip_check") == "on" then
        -- OPTIMIZATION: get_client_ip() is cached in ngx.ctx after first call
        if match_ip_rule('whiteip.rule', get_client_ip()) then
            return true
        end
     end
end

--deny black ip (static blacklist from blackip.rule)
local function black_ip_check()
     if cfg("black_ip_check") == "on" then
        -- OPTIMIZATION: get_client_ip() is cached in ngx.ctx after first call
        if match_ip_rule('blackip.rule', get_client_ip()) then
            log_record('BlackList_IP',var.request_uri,"_","_")
            if is_waf_enabled() == "on" then
                ngx.exit(403)
                return true
            end
        end
     end
end

--deny dynamic black ip (auto-banned by CC, with TTL auto-expire)
local function dynamic_black_ip_check()
    local block_ttl = tonumber(cfg("cc_block_ttl"))
    if block_ttl == nil or block_ttl <= 0 then
        return false
    end
    local badGuys = shared.badGuys
    if badGuys == nil then
        return false
    end
    -- OPTIMIZATION: get_client_ip() is cached in ngx.ctx after first call
    local CLIENT_IP = get_client_ip()
    if badGuys:get(CLIENT_IP) then
        log_record('Dynamic_Block_IP',var.request_uri,"_","_")
        if is_waf_enabled() == "on" then
            ngx.exit(403)
            return true
        end
    end
    return false
end

--allow white url
--whiteurl.rule supports two formats:
--  /path/                          -> default: skip url_attack only
--  /path/ user_agent,referer,...    -> skip specified checks
--Available skip checks: user_agent,referer,url_attack,url_args,cookie,post,file_upload,cc
--Lines starting with # are comments
--Uses string.find (plain mode) for path matching to avoid PCRE JIT overhead
local WHITEURL_SKIP_VALID = {
    user_agent = true, referer = true, url_attack = true, url_args = true,
    cookie = true, post = true, file_upload = true, cc = true,
}

--Worker-level cache for parsed whiteurl.rule (extended format)
local worker_whiteurl_cache = {}

--Check if a string contains regex metacharacters
local function has_regex_metachar(s)
    return s:find("[()%.%[%]%*%+%?%^%$|\\]") ~= nil
end

--Parse whiteurl.rule: separate plain paths from extended (path+skips) rules
--Returns: { plain_rules={path1,path2,...}, extended={ {path="/legacy/", skips={...}, is_regex=bool} } }
local function parse_whiteurl_extended(entry)
    local cached = worker_whiteurl_cache[entry]
    local now = ngx.time()
    if cached and cached.mtime == entry.mtime and (now - cached.last_check) < RULE_CACHE_TTL then
        return cached
    end

    local plain_rules = {}
    local extended = {}
    for _, line in ipairs(entry.rules) do
        local trimmed = line:gsub("^%s+", ""):gsub("%s+$", "")
        if trimmed ~= "" and trimmed:sub(1, 1) ~= "#" then
            -- try to split path and optional skip list
            local path, skip_str = trimmed:match("^(%S+)%s+(.+)$")
            if path and skip_str then
                -- extended format: /path/ check1,check2,...
                local skips = {}
                for check_name in skip_str:gmatch("([^,]+)") do
                    check_name = check_name:gsub("^%s+", ""):gsub("%s+$", ""):lower()
                    if WHITEURL_SKIP_VALID[check_name] then
                        skips[check_name] = true
                    end
                end
                if next(skips) ~= nil then
                    table.insert(extended, {
                        path = path,
                        skips = skips,
                        is_regex = has_regex_metachar(path),
                    })
                else
                    -- invalid skip list, treat as plain path
                    table.insert(plain_rules, path)
                end
            else
                -- plain format: /path/ (no skip list, default: skip url_attack only)
                table.insert(plain_rules, trimmed)
            end
        end
    end

    cached = {
        mtime = entry.mtime,
        plain_rules = plain_rules,
        extended = extended,
        last_check = now,
    }
    worker_whiteurl_cache[entry] = cached
    return cached
end

local function white_url_check()
    if cfg("white_url_check") == "on" then
        local entry = get_rule_entry('whiteurl.rule')
        if entry == nil or entry.empty then return false end
        local REQ_PATH = var.uri or var.request_uri
        local FULL_REQ_URI = var.request_uri

        -- Parse extended format (path + optional skip checks)
        local parsed = parse_whiteurl_extended(entry)

        -- Check extended rules first (longest match priority)
        -- For plain paths: use prefix match (string.sub)
        -- For regex paths (e.g. /ipinfo$): use ngx.re.find
        if REQ_PATH and #parsed.extended > 0 then
            local best_skips = nil
            local best_len = 0
            for _, rule in ipairs(parsed.extended) do
                local rp = rule.path
                local matched = false
                if rule.is_regex then
                    -- regex path: use ngx.re.find (anchored at start via ^ in pattern)
                    matched = rulematch(REQ_PATH, rp, "joi") ~= nil
                else
                    -- plain path: prefix match
                    if #REQ_PATH >= #rp and string.sub(REQ_PATH, 1, #rp) == rp then
                        matched = true
                    end
                end
                if matched and #rp > best_len then
                    best_skips = rule.skips
                    best_len = #rp
                end
            end
            if best_skips then
                return best_skips  -- return the skip config table
            end
            -- also check full URI for extended rules with query strings
            if FULL_REQ_URI and FULL_REQ_URI ~= REQ_PATH then
                for _, rule in ipairs(parsed.extended) do
                    local rp = rule.path
                    local matched = false
                    if rule.is_regex then
                        matched = rulematch(FULL_REQ_URI, rp, "joi") ~= nil
                    else
                        if #FULL_REQ_URI >= #rp and string.sub(FULL_REQ_URI, 1, #rp) == rp then
                            matched = true
                        end
                    end
                    if matched and #rp > best_len then
                        best_skips = rule.skips
                        best_len = #rp
                    end
                end
                if best_skips then
                    return best_skips
                end
            end
        end

        -- Check plain rules (prefix match, same as extended format)
        local function matches_plain(target)
            if target == nil then return false end
            for _, rule in ipairs(parsed.plain_rules) do
                -- prefix match: target starts with rule path
                if #target >= #rule and string.sub(target, 1, #rule) == rule then
                    return true
                end
            end
            -- Fall back to regex for complex whitelist patterns (from entry.combined)
            if entry.combined ~= nil and rulematch(target, entry.combined, "joi") then
                return true
            end
            return false
        end

        -- Plain rules: default behavior = skip url_attack only
        if matches_plain(REQ_PATH) then
            return { url_attack = true }
        end
        if FULL_REQ_URI ~= nil and FULL_REQ_URI ~= REQ_PATH and matches_plain(FULL_REQ_URI) then
            return { url_attack = true }
        end
    end
    return false
end

--check if UA is whitelisted (search engine bots skip UA blacklist only)
--whiteua.rule contains 50 plain-string bot names (Googlebot, bingbot, etc.)
--Uses string.find (plain mode) instead of ngx.re.find for each entry
--This avoids PCRE JIT overhead for simple substring matching
--OPTIMIZATION: bloom-filter style pre-check — only run 50 string.find calls
--if UA contains none of the common bot markers (bot/spider/crawl/etc.)
--This skips the full loop for 99% of normal traffic
local BOT_MARKERS = { "bot", "spider", "crawl", "slurp", "archiver", "feed", "index" }
local function is_white_ua()
    if cfg("white_ua_check") == "on" then
        local USER_AGENT = var.http_user_agent
        if USER_AGENT ~= nil then
            -- OPTIMIZATION: quick bloom-filter check before full 50-rule scan
            -- If UA doesn't contain any bot marker, skip the full loop
            local ua_lower = string.lower(USER_AGENT)
            local has_bot_marker = false
            for _, marker in ipairs(BOT_MARKERS) do
                if string_find(ua_lower, marker, 1, true) then
                    has_bot_marker = true
                    break
                end
            end
            if not has_bot_marker then
                return false
            end
            local entry = get_rule_entry('whiteua.rule')
            if entry == nil or entry.empty then return false end
            -- Fast path: plain-string rules via string.find
            if entry.fast_hash then
                for _, rule in ipairs(entry.fast_rules) do
                    if string_find(USER_AGENT, rule, 1, true) then
                        return true
                    end
                end
            end
            -- Fall back to regex for complex patterns
            if entry.combined ~= nil then
                if rulematch(USER_AGENT, entry.combined, "ijo") then
                    return true
                end
            end
        end
    end
    return false
end

--deny cc attack (sliding window via incr + TTL)
local worker_cc_count = nil
local worker_cc_seconds = nil
local worker_cc_rate_str = nil
local CC_RATE_CACHE_TTL = 30
local worker_cc_rate_last_sync = 0

local function cc_attack_check()
    if cfg("cc_check") == "on" then
        -- OPTIMIZATION: get_client_ip() is cached in ngx.ctx after first call
        local CLIENT_IP = get_client_ip()
        local CC_TOKEN = "cc:" .. CLIENT_IP
        local limit = shared.limit
        if limit == nil then return false end

        local cc_rate = cfg("cc_rate")
        local now = ngx.time()
        if cc_rate ~= worker_cc_rate_str or (now - worker_cc_rate_last_sync) > CC_RATE_CACHE_TTL then
            local shared_count = limit:get("cc_rate_count")
            local shared_seconds = limit:get("cc_rate_seconds")
            local shared_rate_str = limit:get("cc_rate_str")
            if shared_rate_str == cc_rate and shared_count and shared_seconds then
                worker_cc_count = shared_count
                worker_cc_seconds = shared_seconds
                worker_cc_rate_str = cc_rate
                worker_cc_rate_last_sync = now
            else
                local parsed_count = tonumber(string.match(cc_rate, '^(%d+)/'))
                local parsed_seconds = tonumber(string.match(cc_rate, '/(%d+)$'))
                if parsed_count and parsed_seconds then
                    limit:set("cc_rate_count", parsed_count, 300)
                    limit:set("cc_rate_seconds", parsed_seconds, 300)
                    limit:set("cc_rate_str", cc_rate, 300)
                else
                    -- Invalid cc_rate (e.g. "abc" or "10"): CC protection would
                    -- silently fail open. Log an error so the misconfig is visible.
                    ngx.log(ngx.ERR, "[NginxGuard] invalid cc_rate config: ",
                        tostring(cc_rate), " (expected '<count>/<seconds>'), CC check disabled")
                end
                worker_cc_count = parsed_count
                worker_cc_seconds = parsed_seconds
                worker_cc_rate_str = cc_rate
                worker_cc_rate_last_sync = now
            end
        end
        local CCcount = worker_cc_count
        local CCseconds = worker_cc_seconds
        if CCcount == nil or CCseconds == nil then return false end

        local count = limit:incr(CC_TOKEN, 1, 0, CCseconds)
        if count == nil then
            count = 1
            limit:set(CC_TOKEN, 1, CCseconds)
        end

        if count > CCcount then
            log_record('CC_Attack', var.request_uri, "-", "-")
            local block_ttl = tonumber(cfg("cc_block_ttl"))
            if block_ttl and block_ttl > 0 then
                local badGuys = shared.badGuys
                -- OPTIMIZATION: reuse already-cached CLIENT_IP from ngx.ctx
                if badGuys and not badGuys:get(CLIENT_IP) then
                    badGuys:set(CLIENT_IP, 1, block_ttl)
                    log_record('CC_AutoBan', var.request_uri, "_", "ban_" .. block_ttl .. "s")
                end
            end
            if is_waf_enabled() == "on" then
                ngx.exit(403)
            end
            return true
        end
    end
    return false
end

--deny cookie
local function cookie_attack_check()
    if cfg("cookie_check") == "on" then
        local cookie_entry = get_rule_entry('cookie.rule')
        if cookie_entry == nil or cookie_entry.empty then
            return false
        end
        local USER_COOKIE = var.http_cookie
        if USER_COOKIE ~= nil then
            local matched = match_rule_entry(cookie_entry, USER_COOKIE, "joi")
            if not matched and has_encode_markers(USER_COOKIE) then
                local decoded, changed = full_decode(USER_COOKIE)
                if changed then
                    matched = match_rule_entry(cookie_entry, decoded, "joi")
                end
            end
            if matched then
                log_record('Deny_Cookie',var.request_uri,"-",matched)
                if is_waf_enabled() == "on" then
                    waf_output()
                    return true
                end
            end
        end
    end
    return false
end

--deny url
local function url_attack_check()
    if cfg("url_check") == "on" then
        local url_entry = get_rule_entry('url.rule')
        if url_entry == nil or url_entry.empty then
            return false
        end
        local REQ_URI = var.request_uri
        local matched = match_rule_entry(url_entry, REQ_URI, "joi")
        if not matched and string_find(REQ_URI, "%", 1, true) then
            local decoded, changed = full_decode(REQ_URI)
            if changed then
                matched = match_rule_entry(url_entry, decoded, "joi")
            end
        end
        if matched then
            log_record('Deny_URL',REQ_URI,"-",matched)
            if is_waf_enabled() == "on" then
                waf_output()
                return true
            end
        end
    end
    return false
end

--deny url args
local function url_args_attack_check()
    if cfg("url_args_check") == "on" then
        local args_entry = get_rule_entry('args.rule')
        if args_entry == nil or args_entry.empty then
            return false
        end
        local ok, REQ_ARGS, REQ_ARGS_ERR = pcall(req_get_uri_args, MAX_URI_ARGS_PARSE)
        if not ok or REQ_ARGS == nil then
            return false
        end
        -- OPTIMIZATION: if no args at all, skip immediately
        -- ngx.req.get_uri_args returns empty table for /path (no ?query)
        -- Avoids entering the pairs() loop + match_any_rule overhead
        if next(REQ_ARGS) == nil then
            return false
        end
        for key, val in pairs(REQ_ARGS) do
            -- check parameter name (key)
            if key and type(key) == "string" and #key > 0 then
                local matched = match_rule_entry(args_entry, key, "joi")
                if not matched and has_encode_markers(key) then
                    local decoded_key, changed = full_decode(key)
                    if changed then
                        matched = match_rule_entry(args_entry, decoded_key, "joi")
                    end
                end
                if matched then
                    log_record('Deny_URL_Args',var.request_uri,"key:"..key,matched)
                    if is_waf_enabled() == "on" then
                        waf_output()
                        return true
                    end
                end
            end
            -- check parameter value
            local ARGS_DATA
            if type(val) == 'table' then
                ARGS_DATA = safe_table_concat(val, " ")
            else
                ARGS_DATA = val
            end
            if ARGS_DATA and type(ARGS_DATA) ~= "boolean" then
                    local matched = match_rule_entry(args_entry, ARGS_DATA, "joi")
                if not matched and has_encode_markers(ARGS_DATA) then
                    local decoded, changed = full_decode(ARGS_DATA)
                    if changed then
                            matched = match_rule_entry(args_entry, decoded, "joi")
                    end
                end
                if matched then
                    log_record('Deny_URL_Args',var.request_uri,"-",matched)
                    if is_waf_enabled() == "on" then
                        waf_output()
                        return true
                    end
                end
            end
        end
        if REQ_ARGS_ERR == "truncated" then
            local RAW_ARGS = var.args
            if RAW_ARGS and #RAW_ARGS > 0 then
                local matched = match_rule_entry(args_entry, RAW_ARGS, "joi")
                local normalized_args = nil
                if not matched and string_find(RAW_ARGS, "+", 1, true) then
                    normalized_args = string_gsub(RAW_ARGS, "+", " ")
                    matched = match_rule_entry(args_entry, normalized_args, "joi")
                end
                if not matched and has_encode_markers(RAW_ARGS) then
                    local decoded, changed = full_decode(RAW_ARGS)
                    if changed then
                        matched = match_rule_entry(args_entry, decoded, "joi")
                    end
                end
                if not matched and normalized_args and has_encode_markers(normalized_args) then
                    local decoded, changed = full_decode(normalized_args)
                    if changed then
                        matched = match_rule_entry(args_entry, decoded, "joi")
                    end
                end
                if matched then
                    log_record('Deny_URL_Args', var.request_uri, "truncated_query", matched)
                    if is_waf_enabled() == "on" then
                        waf_output()
                        return true
                    end
                end
            end
        end
    end
    return false
end

--deny user agent (skip if UA is whitelisted, e.g. Googlebot)
local function user_agent_attack_check()
    if cfg("user_agent_check") == "on" then
        if is_white_ua() then
            return false
        end
        local ua_entry = get_rule_entry('useragent.rule')
        if ua_entry == nil or ua_entry.empty then
            return false
        end
        local USER_AGENT = var.http_user_agent
        if USER_AGENT ~= nil then
            local matched = match_rule_entry(ua_entry, USER_AGENT, "ijo")
            if matched then
                log_record('Deny_USER_AGENT',var.request_uri,"-",matched)
                if is_waf_enabled() == "on" then
                    waf_output()
                    return true
                end
            end
        end
    end
    return false
end

--deny referer
local function referer_check()
    if cfg("referer_check") == "on" then
        local referer_entry = get_rule_entry('referer.rule')
        if referer_entry == nil or referer_entry.empty then
            return false
        end
        local REFERER = var.http_referer
        if REFERER ~= nil then
            local matched = match_rule_entry(referer_entry, REFERER, "joi")
            if matched then
                log_record('Deny_Referer', var.request_uri, "-", matched)
                if is_waf_enabled() == "on" then
                    waf_output()
                    return true
                end
            end
        end
    end
    return false
end

-- Extract filenames from multipart Content-Disposition headers
local function extract_filenames_from_multipart()
    local filenames = {}
    local function append_filenames_from_data(data)
        if data == nil or not string_find(data, "filename", 1, true) then
            return
        end
        for m in re_gmatch(data, [[filename="([^"]*)"]], "ijo") do
            if m[1] and m[1] ~= "" then table_insert(filenames, m[1]) end
        end
        for m in re_gmatch(data, [[filename=([^";\r\n]+)]], "ijo") do
            if m[1] and m[1] ~= "" then table_insert(filenames, m[1]) end
        end
        for m in re_gmatch(data, [[filename\*=UTF-8''([^;\r\n]+)]], "ijo") do
            if m[1] and m[1] ~= "" then table_insert(filenames, unescape(m[1])) end
        end
    end
    local body = req_get_body_data()

    if body then
        append_filenames_from_data(body)
        return filenames
    end

    local file = req_get_body_file()
    if not file then return filenames end
    local f = io.open(file, "rb")
    if not f then return filenames end

    local chunk_size = 65536
    local prev_tail = ""
    local scan_limit = cfg_number("upload_filename_scan_limit", DEFAULT_UPLOAD_FILENAME_SCAN_LIMIT)
    local scanned = 0

    while true do
        if scan_limit > 0 and scanned >= scan_limit then
            break
        end
        local read_size = chunk_size
        if scan_limit > 0 then
            local remaining = scan_limit - scanned
            if remaining < read_size then
                read_size = remaining
            end
        end
        local chunk = f:read(read_size)
        if not chunk then break end
        scanned = scanned + #chunk
        local data = prev_tail .. chunk

        append_filenames_from_data(data)

        if #data > 512 then
            prev_tail = string_sub(data, -512)
        else
            prev_tail = data
        end
    end
    f:close()
    return filenames
end

--deny file upload by extension
local function file_upload_check()
    if cfg("file_upload_check") == "on" then
        local fileext_entry = get_rule_entry('fileext.rule')
        if fileext_entry == nil or fileext_entry.empty then
            return false
        end
        local CONTENT_TYPE = var.content_type
        if CONTENT_TYPE == nil then return false end
        local content_type = string_lower(CONTENT_TYPE)
        if not string_find(content_type, "multipart/form-data", 1, true) then
            return false
        end
        local ok = pcall(req_read_body)
        if not ok then return false end

        local filenames = extract_filenames_from_multipart()
        if filenames == nil or #filenames == 0 then return false end

        for _, fname in ipairs(filenames) do
            local matched = match_rule_entry(fileext_entry, fname, "joi")
            if matched then
                log_record('Deny_File_Upload', var.request_uri, "-", matched)
                if is_waf_enabled() == "on" then
                    waf_output()
                    return true
                end
            end
        end
    end
    return false
end

--deny post (form + JSON body)
local function post_attack_check()
    if cfg("post_check") == "on" then
        local post_entry = get_rule_entry('post.rule')
        if post_entry == nil or post_entry.empty then
            return false
        end
        -- OPTIMIZATION 1: skip body-less methods early
        local METHOD = req_get_method()
        if is_bodyless_method(METHOD) then
            return false
        end

        local ok = pcall(req_read_body)
        if not ok then return false end
        local CONTENT_TYPE = var.content_type
        local content_type = CONTENT_TYPE and string_lower(CONTENT_TYPE) or nil
        local is_form_urlencoded = content_type
            and string_find(content_type, "application/x-www-form-urlencoded", 1, true) ~= nil
        local is_multipart_form = content_type
            and string_find(content_type, "multipart/form-data", 1, true) ~= nil
        local should_parse_post_args = is_form_urlencoded
        local waf_enabled = is_waf_enabled() == "on"

        -- 1. Parse key/value pairs only for form-urlencoded POSTs.
        -- JSON/XML/plain-text bodies go straight to raw body scanning.
        local ok2, POST_ARGS, POST_ARGS_ERR
        if should_parse_post_args then
            ok2, POST_ARGS, POST_ARGS_ERR = pcall(req_get_post_args)
        end
        if ok2 and POST_ARGS ~= nil then
            for key, val in pairs(POST_ARGS) do
                -- check parameter name (key)
                if key and type(key) == "string" and #key > 0 then
                    local matched_key = match_rule_entry(post_entry, key, "joi")
                    if not matched_key and has_encode_markers(key) then
                        local decoded_key, changed = full_decode(key)
                        if changed then
                            matched_key = match_rule_entry(post_entry, decoded_key, "joi")
                        end
                    end
                    if matched_key then
                        log_record('Deny_URL_POST', var.request_uri, "key:"..key, matched_key)
                        if waf_enabled then
                            waf_output()
                            return true
                        end
                    end
                end
                -- check parameter value
                local POST_DATA
                if type(val) == 'table' then
                    POST_DATA = safe_table_concat(val, " ")
                else
                    POST_DATA = val
                end
                if POST_DATA and type(POST_DATA) ~= "boolean" then
                        local matched = match_rule_entry(post_entry, POST_DATA, "joi")
                    if not matched and has_encode_markers(POST_DATA) then
                        local decoded, changed = full_decode(POST_DATA)
                        if changed then
                                matched = match_rule_entry(post_entry, decoded, "joi")
                        end
                    end
                    if matched then
                        log_record('Deny_URL_POST', var.request_uri, "-", matched)
                        if waf_enabled then
                            waf_output()
                            return true
                        end
                    end
                end
            end
            -- application/x-www-form-urlencoded has already been fully inspected
            -- via parsed key/value pairs, so skip a second full-body scan
            -- unless OpenResty reported truncation.
            if is_form_urlencoded and POST_ARGS_ERR ~= "truncated" then
                return false
            end
        end

        -- 2. Try raw body (JSON, XML, etc.)
        local body = req_get_body_data()
        if body == nil then
            local file = req_get_body_file()
            if file then
                local f = io.open(file, "rb")
                if f then
                    local file_size = f:seek("end")
                    f:seek("set", 0)
                    local post_body_scan_limit = cfg_number("post_body_scan_limit", MAX_INSPECTABLE_BODY_FILE_SIZE)
                    if post_body_scan_limit <= 0 then
                        post_body_scan_limit = MAX_INSPECTABLE_BODY_FILE_SIZE
                    end
                    if (not is_multipart_form) and file_size and file_size > post_body_scan_limit then
                        log_record('Deny_URL_POST_Oversize', var.request_uri,
                            "size:" .. tostring(file_size),
                            "max:" .. tostring(post_body_scan_limit))
                        f:close()
                        if waf_enabled then
                            waf_output()
                        end
                        return true
                    end
                      if is_multipart_form and not is_multipart_streaming_enabled() then
                          f:close()
                          return false
                      end
                    local chunk_size = 65536
                    local max_scan = is_multipart_form and post_body_scan_limit or file_size
                    local overlap = 2048
                    local total = 0
                    local prev_tail = ""
                    local found = false

                    while (max_scan == nil or total < max_scan) and not found do
                        local chunk = f:read(chunk_size)
                        if not chunk then break end
                        total = total + #chunk
                        local data = prev_tail .. chunk
                          local matched = match_rule_entry(post_entry, data, "joi")
                        if not matched and has_encode_markers(data) then
                            local decoded, changed = full_decode(data)
                            if changed then
                                  matched = match_rule_entry(post_entry, decoded, "joi")
                            end
                        end
                        if matched then
                            log_record('Deny_URL_POST', var.request_uri, "-", matched)
                            f:close()
                            if waf_enabled then
                                waf_output()
                            end
                            return true
                        end
                        if #data > overlap then
                            prev_tail = string_sub(data, -overlap)
                        else
                            prev_tail = data
                        end
                    end
                    f:close()
                    return false
                end
            end
        end
        if body and #body > 0 then
            local matched = match_rule_entry(post_entry, body, "joi")
            if not matched and has_encode_markers(body) then
                local decoded, changed = full_decode(body)
                if changed then
                    matched = match_rule_entry(post_entry, decoded, "joi")
                end
            end
            if matched then
                log_record('Deny_URL_POST', var.request_uri, "-", matched)
                if waf_enabled then
                    waf_output()
                    return true
                end
            end
        end
    end
    return false
end

--=========================================================================
-- OPTIMIZATION 1: waf_main with request-type short-circuit
-- GET requests skip file_upload_check and post_attack_check entirely
-- POST requests run all checks
-- This saves ~2 function calls + body reading for GET requests
--=========================================================================
local function waf_main()
    if var.waf_enable == "off" then
        return
    end
    if is_waf_enabled() == "off" then
        return
    end
    -- IP checks (always run)
    if white_ip_check() then
        return
    end
    if dynamic_black_ip_check() then
        return
    end
    if black_ip_check() then
        return
    end
    -- whiteurl.rule: per-URL skip checks
    -- Returns: false (no match) or table of skip check names
    -- Plain format (/path/) defaults to {url_attack=true}
    -- Extended format (/path/ user_agent,referer,...) skips specified checks
    local url_skips = white_url_check()
    -- Determine request type early (used for multiple short-circuits below)
    local METHOD = req_get_method()
    local is_bodyless = is_bodyless_method(METHOD)

    -- Request-type checks (url_skips can skip individual checks)
    if not (url_skips and url_skips.user_agent) then
        if user_agent_attack_check() then
            return
        end
    end
    if not (url_skips and url_skips.referer) then
        if referer_check() then
            return
        end
    end
    if not (url_skips and url_skips.cc) then
        if cc_attack_check() then
            return
        end
    end

    -- OPTIMIZATION 1: request-type short-circuit
    -- GET/HEAD/OPTIONS skip file_upload and post checks (controlled by bodyless config)
    if not is_bodyless then
        if not (url_skips and url_skips.file_upload) then
            if file_upload_check() then
                return
            end
        end
    end

    -- White-listed URL: skip url_attack_check if configured.
    -- url_args_check, cookie_check, post_check still apply unless explicitly skipped.
    if not (url_skips and url_skips.url_attack) then
        if url_attack_check() then
            return
        end
    end
    if not (url_skips and url_skips.url_args) then
        if url_args_attack_check() then
            return
        end
    end

    -- Cookie check: moved after URL/Args so short-circuit saves 1 regex on attack
    -- GET Cookie attacks exist (XSS injection via cookie), so we still check all methods
    if not (url_skips and url_skips.cookie) then
        if cookie_attack_check() then
            return
        end
    end

    if not is_bodyless then
        if not (url_skips and url_skips.post) then
            if post_attack_check() then
                return
            end
        end
    end
end

--run NginxGuard, pcall to prevent 500 on any unexpected error
local ok, err = pcall(waf_main)
if not ok then
    ngx.log(ngx.ERR, "waf_main error: ", err)
end
