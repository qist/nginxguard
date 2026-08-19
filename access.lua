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
local string_sub = string.sub
local string_char = string.char

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
--Uses string.find (plain mode) instead of ngx.re.find for each whitelist entry
--This avoids PCRE JIT overhead for simple path patterns like /static/, /api/login
local function white_url_check()
    if cfg("white_url_check") == "on" then
        local entry = get_rule_entry('whiteurl.rule')
        if entry == nil or entry.empty then return false end
        local REQ_URI = var.request_uri
        -- Check plain-string rules first (fast path, no regex)
        if entry.fast_hash then
            for _, rule in ipairs(entry.fast_rules) do
                if string_find(REQ_URI, rule, 1, true) then
                    return true
                end
            end
        end
        -- Fall back to regex for complex whitelist patterns
        if entry.combined ~= nil then
            if rulematch(REQ_URI, entry.combined, "joi") then
                return true
            end
        end
    end
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
        local USER_COOKIE = var.http_cookie
        if USER_COOKIE ~= nil then
            local matched = match_any_rule('cookie.rule', USER_COOKIE, "joi")
            if not matched and has_encode_markers(USER_COOKIE) then
                local decoded, changed = full_decode(USER_COOKIE)
                if changed then
                    matched = match_any_rule('cookie.rule', decoded, "joi")
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
        local REQ_URI = var.request_uri
        local matched = match_any_rule('url.rule', REQ_URI, "joi")
        if not matched and string_find(REQ_URI, "%", 1, true) then
            local decoded, changed = full_decode(REQ_URI)
            if changed then
                matched = match_any_rule('url.rule', decoded, "joi")
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
        local ok, REQ_ARGS = pcall(req_get_uri_args)
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
                local matched = match_any_rule('args.rule', key, "joi")
                if not matched and has_encode_markers(key) then
                    local decoded_key = full_decode(key)
                    if decoded_key ~= key then
                        matched = match_any_rule('args.rule', decoded_key, "joi")
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
                ARGS_DATA = table_concat(val, " ")
            else
                ARGS_DATA = val
            end
            if ARGS_DATA and type(ARGS_DATA) ~= "boolean" then
                local matched = match_any_rule('args.rule', ARGS_DATA, "joi")
                if not matched and has_encode_markers(ARGS_DATA) then
                    local decoded, changed = full_decode(ARGS_DATA)
                    if changed then
                        matched = match_any_rule('args.rule', decoded, "joi")
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
    end
    return false
end

--deny user agent (skip if UA is whitelisted, e.g. Googlebot)
local function user_agent_attack_check()
    if cfg("user_agent_check") == "on" then
        if is_white_ua() then
            return false
        end
        local USER_AGENT = var.http_user_agent
        if USER_AGENT ~= nil then
            local matched = match_any_rule('useragent.rule', USER_AGENT, "ijo")
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
        local REFERER = var.http_referer
        if REFERER ~= nil then
            local matched = match_any_rule('referer.rule', REFERER, "joi")
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
    local body = req_get_body_data()

    if body then
        for m in re_gmatch(body, [[filename="([^"]*)"]], "ijo") do
            if m[1] and m[1] ~= "" then table_insert(filenames, m[1]) end
        end
        for m in re_gmatch(body, [[filename=([^";\r\n]+)]], "ijo") do
            if m[1] and m[1] ~= "" then table_insert(filenames, m[1]) end
        end
        for m in re_gmatch(body, [[filename\*=UTF-8''([^;\r\n]+)]], "ijo") do
            if m[1] and m[1] ~= "" then table_insert(filenames, unescape(m[1])) end
        end
        return filenames
    end

    local file = req_get_body_file()
    if not file then return filenames end
    local f = io.open(file, "rb")
    if not f then return filenames end

    local chunk_size = 65536
    local max_scan = 2097152
    local total = 0
    local prev_tail = ""

    while total < max_scan do
        local chunk = f:read(chunk_size)
        if not chunk then break end
        total = total + #chunk
        local data = prev_tail .. chunk

        for m in re_gmatch(data, [[filename="([^"]*)"]], "ijo") do
            if m[1] and m[1] ~= "" then table_insert(filenames, m[1]) end
        end
        for m in re_gmatch(data, [[filename=([^";\r\n]+)]], "ijo") do
            if m[1] and m[1] ~= "" then table_insert(filenames, m[1]) end
        end
        for m in re_gmatch(data, [[filename\*=UTF-8''([^;\r\n]+)]], "ijo") do
            if m[1] and m[1] ~= "" then table_insert(filenames, unescape(m[1])) end
        end

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
        local CONTENT_TYPE = var.content_type
        if CONTENT_TYPE == nil then return false end
        if not string_find(CONTENT_TYPE, "multipart/form%-data", 1) then
            return false
        end
        local ok = pcall(req_read_body)
        if not ok then return false end

        local filenames = extract_filenames_from_multipart()
        if filenames == nil or #filenames == 0 then return false end

        for _, fname in ipairs(filenames) do
            local matched = match_any_rule('fileext.rule', fname, "joi")
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
        -- OPTIMIZATION 1: skip body-less methods early
        local METHOD = req_get_method()
        if METHOD == "GET" or METHOD == "HEAD" or METHOD == "OPTIONS" or METHOD == "DELETE" then
            return false
        end

        local ok = pcall(req_read_body)
        if not ok then return false end

        -- 1. Try form-encoded args (fast path)
        local ok2, POST_ARGS = pcall(req_get_post_args)
        if ok2 and POST_ARGS ~= nil then
            for key, val in pairs(POST_ARGS) do
                -- check parameter name (key)
                if key and type(key) == "string" and #key > 0 then
                    local matched_key = match_any_rule('post.rule', key, "joi")
                    if not matched_key and has_encode_markers(key) then
                        local decoded_key = full_decode(key)
                        if decoded_key ~= key then
                            matched_key = match_any_rule('post.rule', decoded_key, "joi")
                        end
                    end
                    if matched_key then
                        log_record('Deny_URL_POST', var.request_uri, "key:"..key, matched_key)
                        if is_waf_enabled() == "on" then
                            waf_output()
                            return true
                        end
                    end
                end
                -- check parameter value
                local POST_DATA
                if type(val) == 'table' then
                    POST_DATA = table_concat(val, " ")
                else
                    POST_DATA = val
                end
                if POST_DATA and type(POST_DATA) ~= "boolean" then
                    local matched = match_any_rule('post.rule', POST_DATA, "joi")
                    if not matched and has_encode_markers(POST_DATA) then
                        local decoded, changed = full_decode(POST_DATA)
                        if changed then
                            matched = match_any_rule('post.rule', decoded, "joi")
                        end
                    end
                    if matched then
                        log_record('Deny_URL_POST', var.request_body, "-", matched)
                        if is_waf_enabled() == "on" then
                            waf_output()
                            return true
                        end
                    end
                end
            end
        end

        -- 2. Try raw body (JSON, XML, etc.)
        local body = req_get_body_data()
        if body == nil then
            local file = req_get_body_file()
            if file then
                local f = io.open(file, "rb")
                if f then
                    local chunk_size = 65536
                    local max_scan = 2097152
                    local overlap = 2048
                    local total = 0
                    local prev_tail = ""
                    local found = false

                    while total < max_scan and not found do
                        local chunk = f:read(chunk_size)
                        if not chunk then break end
                        total = total + #chunk
                        local data = prev_tail .. chunk
                        local matched = match_any_rule('post.rule', data, "joi")
                        if not matched and has_encode_markers(data) then
                            local decoded, changed = full_decode(data)
                            if changed then
                                matched = match_any_rule('post.rule', decoded, "joi")
                            end
                        end
                        if matched then
                            log_record('Deny_URL_POST', var.request_uri, "-", matched)
                            f:close()
                            if is_waf_enabled() == "on" then
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
            local matched = match_any_rule('post.rule', body, "joi")
            if not matched and has_encode_markers(body) then
                local decoded, changed = full_decode(body)
                if changed then
                    matched = match_any_rule('post.rule', decoded, "joi")
                end
            end
            if matched then
                log_record('Deny_URL_POST', var.request_uri, "-", matched)
                if is_waf_enabled() == "on" then
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
    local url_whitelisted = white_url_check()
    if black_ip_check() then
        return
    end
    -- Determine request type early (used for multiple short-circuits below)
    local METHOD = req_get_method()
    local is_bodyless = (METHOD == "GET" or METHOD == "HEAD" or METHOD == "OPTIONS" or METHOD == "DELETE")

    -- Request-type checks (always run)
    if user_agent_attack_check() then
        return
    end
    if referer_check() then
        return
    end
    if cc_attack_check() then
        return
    end

    -- OPTIMIZATION 1: request-type short-circuit
    -- GET/HEAD/OPTIONS/DELETE: skip file_upload and post checks
    if not is_bodyless then
        if file_upload_check() then
            return
        end
    end

    if not url_whitelisted then
        if url_attack_check() then
            return
        end
        if url_args_attack_check() then
            return
        end
    end

    -- Cookie check: moved after URL/Args so short-circuit saves 1 regex on attack
    -- GET Cookie attacks exist (XSS injection via cookie), so we still check all methods
    if cookie_attack_check() then
        return
    end

    if not is_bodyless then
        if post_attack_check() then
            return
        end
    end
end

--run NginxGuard, pcall to prevent 500 on any unexpected error
local ok, err = pcall(waf_main)
if not ok then
    ngx.log(ngx.ERR, "waf_main error: ", err)
end
