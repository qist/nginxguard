--NginxGuard Action
require 'config'
require 'lib'

--args
local rulematch = ngx.re.find
local unescape = ngx.unescape_uri
local io = require 'io'
local string_find = string.find

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
        s = ngx.re.gsub(s, [[\\u\{([0-9a-fA-F]{1,6})\}]], function(m)
            local code = tonumber(m[1], 16)
            if code and code >= 32 and code <= 126 then return string.char(code) end
            return m[0]
        end, "jo")
        s = ngx.re.gsub(s, [[\\u([0-9a-fA-F]{4})]], function(m)
            local code = tonumber(m[1], 16)
            if code and code >= 32 and code <= 126 then return string.char(code) end
            return m[0]
        end, "jo")
        s = ngx.re.gsub(s, [[\\x([0-9a-fA-F]{2})]], function(m)
            local code = tonumber(m[1], 16)
            if code and code >= 32 and code <= 126 then return string.char(code) end
            return m[0]
        end, "jo")
        s = ngx.re.gsub(s, [[&#x([0-9a-fA-F]{2,4});]], function(m)
            local code = tonumber(m[1], 16)
            if code and code >= 32 and code <= 126 then return string.char(code) end
            return m[0]
        end, "joi")
        s = ngx.re.gsub(s, [[&#(\d{2,3});]], function(m)
            local code = tonumber(m[1])
            if code and code >= 32 and code <= 126 then return string.char(code) end
            return m[0]
        end, "joi")
        if s ~= before then changed = true end
    end
    return s, changed
end

--Quick check: does string contain any encoding markers?
--Used to gate decode operations (avoid regex/decode overhead on normal traffic)
local function has_encode_markers(s)
    if s == nil then return false end
    return string_find(s, "%", 1, true) ~= nil
        or string_find(s, "\\u", 1, true) ~= nil
        or string_find(s, "\\x", 1, true) ~= nil
        or string_find(s, "&#", 1, true) ~= nil
end

--Per-request cached waf_enable (avoids ~13 redundant get_effective_config calls)
local function is_waf_enabled()
    if ngx.ctx._waf_enabled == nil then
        ngx.ctx._waf_enabled = get_effective_config("waf_enable")
    end
    return ngx.ctx._waf_enabled
end

--allow white ip
local function white_ip_check()
     if get_effective_config("white_ip_check") == "on" then
        if match_ip_rule('whiteip.rule', get_client_ip()) then
            return true
        end
     end
end

--deny black ip (static blacklist from blackip.rule)
local function black_ip_check()
     if get_effective_config("black_ip_check") == "on" then
        if match_ip_rule('blackip.rule', get_client_ip()) then
            log_record('BlackList_IP',ngx.var.request_uri,"_","_")
            if is_waf_enabled() == "on" then
                ngx.exit(403)
                return true
            end
        end
     end
end

--deny dynamic black ip (auto-banned by CC, with TTL auto-expire)
local function dynamic_black_ip_check()
    local block_ttl = tonumber(get_effective_config("cc_block_ttl"))
    if block_ttl == nil or block_ttl <= 0 then
        return false
    end
    local badGuys = ngx.shared.badGuys
    if badGuys == nil then
        return false
    end
    local CLIENT_IP = get_client_ip()
    if badGuys:get(CLIENT_IP) then
        log_record('Dynamic_Block_IP',ngx.var.request_uri,"_","_")
        if is_waf_enabled() == "on" then
            ngx.exit(403)
            return true
        end
    end
    return false
end

--allow white url
local function white_url_check()
    if get_effective_config("white_url_check") == "on" then
        local REQ_URI = ngx.var.request_uri
        if match_any_rule('whiteurl.rule', REQ_URI, "joi") then
            return true
        end
    end
end

--check if UA is whitelisted (search engine bots skip UA blacklist only)
local function is_white_ua()
    if get_effective_config("white_ua_check") == "on" then
        local USER_AGENT = ngx.var.http_user_agent
        if USER_AGENT ~= nil then
            if match_any_rule('whiteua.rule', USER_AGENT, "ijo") then
                return true
            end
        end
    end
    return false
end

--deny cc attack (sliding window via incr + TTL)
--Worker-level cc_rate cache with shared dict fallback for cross-worker consistency
local worker_cc_count = nil
local worker_cc_seconds = nil
local worker_cc_rate_str = nil
local CC_RATE_CACHE_TTL = 30  -- re-check shared dict every 30s
local worker_cc_rate_last_sync = 0

local function cc_attack_check()
    if get_effective_config("cc_check") == "on" then
        local CC_TOKEN = "cc:" .. get_client_ip()
        local limit = ngx.shared.limit
        if limit == nil then return false end

        local cc_rate = get_effective_config("cc_rate")
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

        local count, err = limit:incr(CC_TOKEN, 1, 0, CCseconds)
        if count == nil then
            count = 1
            limit:set(CC_TOKEN, 1, CCseconds)
        end

        if count > CCcount then
            log_record('CC_Attack', ngx.var.request_uri, "-", "-")
            local block_ttl = tonumber(get_effective_config("cc_block_ttl"))
            if block_ttl and block_ttl > 0 then
                local badGuys = ngx.shared.badGuys
                if badGuys and not badGuys:get(get_client_ip()) then
                    badGuys:set(get_client_ip(), 1, block_ttl)
                    log_record('CC_AutoBan', ngx.var.request_uri, "_", "ban_" .. block_ttl .. "s")
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
    if get_effective_config("cookie_check") == "on" then
        local USER_COOKIE = ngx.var.http_cookie
        if USER_COOKIE ~= nil then
            -- fast path: match raw first (most cookies have no encoding)
            local matched = match_any_rule('cookie.rule', USER_COOKIE, "joi")
            -- only decode if raw didn't match AND encoding markers present
            if not matched and has_encode_markers(USER_COOKIE) then
                local decoded, changed = full_decode(USER_COOKIE)
                if changed then
                    matched = match_any_rule('cookie.rule', decoded, "joi")
                end
            end
            if matched then
                log_record('Deny_Cookie',ngx.var.request_uri,"-",matched)
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
    if get_effective_config("url_check") == "on" then
        local REQ_URI = ngx.var.request_uri
        -- fast path: match raw URI first
        local matched = match_any_rule('url.rule', REQ_URI, "joi")
        -- only decode if raw didn't match AND '%' present (URI encoding uses %)
        if not matched and string_find(REQ_URI, "%%", 1, true) then
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
    if get_effective_config("url_args_check") == "on" then
        local ok, REQ_ARGS = pcall(ngx.req.get_uri_args)
        if not ok or REQ_ARGS == nil then
            return false
        end
        for key, val in pairs(REQ_ARGS) do
            -- check parameter name (key) for injection
            -- fast path: match raw key first, only decode if markers present
            if key and type(key) == "string" and #key > 0 then
                local matched = match_any_rule('args.rule', key, "joi")
                if not matched and has_encode_markers(key) then
                    local decoded_key = full_decode(key)
                    if decoded_key ~= key then
                        matched = match_any_rule('args.rule', decoded_key, "joi")
                    end
                end
                if matched then
                    log_record('Deny_URL_Args',ngx.var.request_uri,"key:"..key,matched)
                    if is_waf_enabled() == "on" then
                        waf_output()
                        return true
                    end
                end
            end
            -- check parameter value
            local ARGS_DATA
            if type(val) == 'table' then
                ARGS_DATA = table.concat(val, " ")
            else
                ARGS_DATA = val
            end
            if ARGS_DATA and type(ARGS_DATA) ~= "boolean" then
                -- fast path: match raw value first
                local matched = match_any_rule('args.rule', ARGS_DATA, "joi")
                -- only decode if raw didn't match AND markers present
                if not matched and has_encode_markers(ARGS_DATA) then
                    local decoded, changed = full_decode(ARGS_DATA)
                    if changed then
                        matched = match_any_rule('args.rule', decoded, "joi")
                    end
                end
                if matched then
                    log_record('Deny_URL_Args',ngx.var.request_uri,"-",matched)
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
    if get_effective_config("user_agent_check") == "on" then
        if is_white_ua() then
            return false
        end
        local USER_AGENT = ngx.var.http_user_agent
        if USER_AGENT ~= nil then
            local matched = match_any_rule('useragent.rule', USER_AGENT, "ijo")
            if matched then
                log_record('Deny_USER_AGENT',ngx.var.request_uri,"-",matched)
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
    if get_effective_config("referer_check") == "on" then
        local REFERER = ngx.var.http_referer
        if REFERER ~= nil then
            local matched = match_any_rule('referer.rule', REFERER, "joi")
            if matched then
                log_record('Deny_Referer', ngx.var.request_uri, "-", matched)
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
-- Only reads header portions, NOT file content (prevents OOM on large uploads)
local function extract_filenames_from_multipart()
    local filenames = {}
    local body = ngx.req.get_body_data()

    if body then
        for m in ngx.re.gmatch(body, [[filename="([^"]*)"]], "ijo") do
            if m[1] and m[1] ~= "" then table.insert(filenames, m[1]) end
        end
        for m in ngx.re.gmatch(body, [[filename=([^";\r\n]+)]], "ijo") do
            if m[1] and m[1] ~= "" then table.insert(filenames, m[1]) end
        end
        for m in ngx.re.gmatch(body, [[filename\*=UTF-8''([^;\r\n]+)]], "ijo") do
            if m[1] and m[1] ~= "" then table.insert(filenames, unescape(m[1])) end
        end
        return filenames
    end

    local file = ngx.req.get_body_file()
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

        for m in ngx.re.gmatch(data, [[filename="([^"]*)"]], "ijo") do
            if m[1] and m[1] ~= "" then table.insert(filenames, m[1]) end
        end
        for m in ngx.re.gmatch(data, [[filename=([^";\r\n]+)]], "ijo") do
            if m[1] and m[1] ~= "" then table.insert(filenames, m[1]) end
        end
        for m in ngx.re.gmatch(data, [[filename\*=UTF-8''([^;\r\n]+)]], "ijo") do
            if m[1] and m[1] ~= "" then table.insert(filenames, unescape(m[1])) end
        end

        if #data > 512 then
            prev_tail = string.sub(data, -512)
        else
            prev_tail = data
        end
    end
    f:close()
    return filenames
end

--deny file upload by extension
local function file_upload_check()
    if get_effective_config("file_upload_check") == "on" then
        local CONTENT_TYPE = ngx.var.content_type
        if CONTENT_TYPE == nil then return false end
        if not string.find(CONTENT_TYPE, "multipart/form%-data", 1) then
            return false
        end
        local ok = pcall(ngx.req.read_body)
        if not ok then return false end

        local filenames = extract_filenames_from_multipart()
        if filenames == nil or #filenames == 0 then return false end

        for _, fname in ipairs(filenames) do
            local matched = match_any_rule('fileext.rule', fname, "joi")
            if matched then
                log_record('Deny_File_Upload', ngx.var.request_uri, "-", matched)
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
    if get_effective_config("post_check") == "on" then
        local METHOD = ngx.req.get_method()
        if METHOD == "GET" or METHOD == "HEAD" or METHOD == "OPTIONS" or METHOD == "DELETE" then
            return false
        end

        local ok = pcall(ngx.req.read_body)
        if not ok then return false end

        -- 1. Try form-encoded args (fast path)
        local ok2, POST_ARGS = pcall(ngx.req.get_post_args)
        if ok2 and POST_ARGS ~= nil then
            for key, val in pairs(POST_ARGS) do
                -- check parameter name (key): match raw first, decode only if markers present
                if key and type(key) == "string" and #key > 0 then
                    local matched_key = match_any_rule('post.rule', key, "joi")
                    if not matched_key and has_encode_markers(key) then
                        local decoded_key = full_decode(key)
                        if decoded_key ~= key then
                            matched_key = match_any_rule('post.rule', decoded_key, "joi")
                        end
                    end
                    if matched_key then
                        log_record('Deny_URL_POST', ngx.var.request_uri, "key:"..key, matched_key)
                        if is_waf_enabled() == "on" then
                            waf_output()
                            return true
                        end
                    end
                end
                -- check parameter value: match raw first, decode only if markers present
                local POST_DATA
                if type(val) == 'table' then
                    POST_DATA = table.concat(val, " ")
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
                        log_record('Deny_URL_POST', ngx.var.request_body, "-", matched)
                        if is_waf_enabled() == "on" then
                            waf_output()
                            return true
                        end
                    end
                end
            end
        end

        -- 2. Try raw body (JSON, XML, etc.)
        local body = ngx.req.get_body_data()
        if body == nil then
            -- body too large, stored in temp file: read in chunks
            local file = ngx.req.get_body_file()
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
                        -- fast path: match raw chunk first
                        local matched = match_any_rule('post.rule', data, "joi")
                        if not matched and has_encode_markers(data) then
                            local decoded, changed = full_decode(data)
                            if changed then
                                matched = match_any_rule('post.rule', decoded, "joi")
                            end
                        end
                        if matched then
                            log_record('Deny_URL_POST', ngx.var.request_uri, "-", matched)
                            f:close()
                            if is_waf_enabled() == "on" then
                                waf_output()
                            end
                            return true
                        end
                        if #data > overlap then
                            prev_tail = string.sub(data, -overlap)
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
            -- fast path: match raw body first
            local matched = match_any_rule('post.rule', body, "joi")
            if not matched and has_encode_markers(body) then
                local decoded, changed = full_decode(body)
                if changed then
                    matched = match_any_rule('post.rule', decoded, "joi")
                end
            end
            if matched then
                log_record('Deny_URL_POST', ngx.var.request_uri, "-", matched)
                if is_waf_enabled() == "on" then
                    waf_output()
                    return true
                end
            end
        end
    end
    return false
end

--NginxGuard main entry
local function waf_main()
    if ngx.var.waf_enable == "off" then
        return
    end
    if is_waf_enabled() == "off" then
        return
    end
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
    if user_agent_attack_check() then
        return
    end
    if referer_check() then
        return
    end
    if cc_attack_check() then
        return
    end
    if cookie_attack_check() then
        return
    end
    if file_upload_check() then
        return
    end
    if not url_whitelisted then
        if url_attack_check() then
            return
        end
        if url_args_attack_check() then
            return
        end
    end
    if post_attack_check() then
        return
    end
end

--run NginxGuard, pcall to prevent 500 on any unexpected error
local ok, err = pcall(waf_main)
if not ok then
    ngx.log(ngx.ERR, "waf_main error: ", err)
end
