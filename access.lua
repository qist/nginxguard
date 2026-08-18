--NginxGuard Action
require 'config'
require 'lib'

--args
local rulematch = ngx.re.find
local unescape = ngx.unescape_uri
local io = require 'io'

--Recursive URL-decode: decode up to 3 layers to catch multi-encoded attacks
--e.g. %25253Cscript -> %253Cscript -> %3Cscript -> <script
local function recursive_unescape(s)
    if s == nil then return s end
    local prev = s
    for _ = 1, 3 do
        local decoded = unescape(prev)
        if decoded == prev then break end  -- stable, no more changes
        prev = decoded
    end
    return prev
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
--Worker-level cc_rate cache (avoids per-request string.match)
local worker_cc_count = nil
local worker_cc_seconds = nil
local worker_cc_rate_str = nil

local function cc_attack_check()
    if get_effective_config("cc_check") == "on" then
        local ATTACK_URI = ngx.var.uri
        -- CC counting granularity:
        --   "ip"     -> count per client IP only (blocks whole-IP CC even with randomized paths)
        --   "ip_uri" -> count per IP+URI (original behavior; only blocks single-path flooding)
        local cc_mode = get_effective_config("cc_mode") or "ip_uri"
        local CC_TOKEN
        if cc_mode == "ip" then
            CC_TOKEN = "cc:" .. get_client_ip()
        else
            CC_TOKEN = "cc:" .. get_client_ip() .. ATTACK_URI
        end
        local limit = ngx.shared.limit
        if limit == nil then return false end

        -- Parse cc_rate once per worker, cache result
        local cc_rate = get_effective_config("cc_rate")
        if cc_rate ~= worker_cc_rate_str then
            worker_cc_rate_str = cc_rate
            worker_cc_count = tonumber(string.match(cc_rate, '^(%d+)/'))
            worker_cc_seconds = tonumber(string.match(cc_rate, '/(%d+)$'))
        end
        local CCcount = worker_cc_count
        local CCseconds = worker_cc_seconds
        if CCcount == nil or CCseconds == nil then return false end

        -- incr with init+TTL: first request creates counter=1 with TTL, subsequent increments
        local count, err = limit:incr(CC_TOKEN, 1, 0, CCseconds)
        if count == nil then
            count = 1
            limit:set(CC_TOKEN, 1, CCseconds)
        end

        if count > CCcount then
            log_record('CC_Attack', ngx.var.request_uri, "-", "-")
            -- auto-ban IP with TTL
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
        -- TTL is set by incr() init, no need for separate expire() call
    end
    return false
end

--deny cookie
local function cookie_attack_check()
    if get_effective_config("cookie_check") == "on" then
        local USER_COOKIE = ngx.var.http_cookie
        if USER_COOKIE ~= nil then
            -- check both raw and recursively decoded cookie to catch multi-encoded attacks
            local matched = match_any_rule('cookie.rule', USER_COOKIE, "joi")
            if not matched then
                local decoded = recursive_unescape(USER_COOKIE)
                if decoded ~= USER_COOKIE then
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
        -- decode URI to catch encoded path traversal (%2e%2e%2f) and encoded sensitive paths
        local REQ_URI = ngx.var.request_uri
        local decoded_uri = recursive_unescape(REQ_URI)
        -- match both raw and decoded URI
        local matched = match_any_rule('url.rule', REQ_URI, "joi")
        if not matched and decoded_uri ~= REQ_URI then
            matched = match_any_rule('url.rule', decoded_uri, "joi")
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
            local ARGS_DATA
            if type(val) == 'table' then
                ARGS_DATA = table.concat(val, " ")
            else
                ARGS_DATA = val
            end
            if ARGS_DATA and type(ARGS_DATA) ~= "boolean" then
                local matched = match_any_rule('args.rule', recursive_unescape(ARGS_DATA), "joi")
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
-- Handles: filename="xxx", filename=xxx, filename*=UTF-8''xxx (RFC 5987)
-- For temp files: reads in 64KB chunks with 512-byte overlap, max 2MB scan
local function extract_filenames_from_multipart()
    local filenames = {}
    local body = ngx.req.get_body_data()

    if body then
        -- Body in memory (≤ client_body_buffer_size): extract filenames
        for m in ngx.re.gmatch(body, [[filename="([^"]*)"]], "ijo") do
            if m[1] and m[1] ~= "" then
                table.insert(filenames, m[1])
            end
        end
        for m in ngx.re.gmatch(body, [[filename=([^";\r\n]+)]], "ijo") do
            if m[1] and m[1] ~= "" then
                table.insert(filenames, m[1])
            end
        end
        -- RFC 5987: filename*=UTF-8''percent-encoded
        for m in ngx.re.gmatch(body, [[filename\*=UTF-8''([^;\r\n]+)]], "ijo") do
            if m[1] and m[1] ~= "" then
                table.insert(filenames, unescape(m[1]))
            end
        end
        return filenames
    end

    -- Body in temp file: read in chunks, extract filenames only (never load full file)
    local file = ngx.req.get_body_file()
    if not file then return filenames end

    local f = io.open(file, "rb")
    if not f then return filenames end

    local chunk_size = 65536    -- 64KB per chunk
    local max_scan = 2097152    -- scan max 2MB (covers multi-file uploads)
    local total = 0
    local prev_tail = ""

    while total < max_scan do
        local chunk = f:read(chunk_size)
        if not chunk then break end
        total = total + #chunk

        -- prepend previous tail for cross-chunk pattern matching
        local data = prev_tail .. chunk

        for m in ngx.re.gmatch(data, [[filename="([^"]*)"]], "ijo") do
            if m[1] and m[1] ~= "" then
                table.insert(filenames, m[1])
            end
        end
        for m in ngx.re.gmatch(data, [[filename=([^";\r\n]+)]], "ijo") do
            if m[1] and m[1] ~= "" then
                table.insert(filenames, m[1])
            end
        end
        for m in ngx.re.gmatch(data, [[filename\*=UTF-8''([^;\r\n]+)]], "ijo") do
            if m[1] and m[1] ~= "" then
                table.insert(filenames, unescape(m[1]))
            end
        end

        -- keep last 512 bytes as overlap for next chunk
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
--Only checks filenames from multipart Content-Disposition headers
--Does NOT read file content into memory
local function file_upload_check()
    if get_effective_config("file_upload_check") == "on" then
        local CONTENT_TYPE = ngx.var.content_type
        if CONTENT_TYPE == nil then return false end
        -- only check multipart form data (file uploads)
        if not string.find(CONTENT_TYPE, "multipart/form%-data", 1) then
            return false
        end
        -- read body (needed for both in-memory and temp file access)
        local ok = pcall(ngx.req.read_body)
        if not ok then return false end

        -- extract filenames from multipart headers (NOT file content)
        local filenames = extract_filenames_from_multipart()
        if filenames == nil or #filenames == 0 then return false end

        -- match each filename against combined rules (fast path)
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
        -- skip non-POST/PUT requests (fix HTTP/2 GET 500 error)
        local METHOD = ngx.req.get_method()
        if METHOD ~= "POST" and METHOD ~= "PUT" and METHOD ~= "PATCH" then
            return false
        end

        -- read body first, pcall to prevent HTTP/2/HTTP/3 errors
        local ok = pcall(ngx.req.read_body)
        if not ok then
            return false
        end

        -- 1. Try form-encoded args (fast: match each arg against combined pattern)
        local ok2, POST_ARGS = pcall(ngx.req.get_post_args)
        if ok2 and POST_ARGS ~= nil then
            for key, val in pairs(POST_ARGS) do
                local POST_DATA
                if type(val) == 'table' then
                    POST_DATA = table.concat(val, " ")
                else
                    POST_DATA = val
                end
                if POST_DATA and type(POST_DATA) ~= "boolean" then
                    local decoded_post = recursive_unescape(POST_DATA)
                    local matched = match_any_rule('post.rule', decoded_post, "joi")
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
        -- Read body in chunks to avoid OOM on large uploads (max 2MB scan)
        local body = ngx.req.get_body_data()
        if body == nil then
            -- body too large, stored in temp file: read in chunks
            local file = ngx.req.get_body_file()
            if file then
                local f = io.open(file, "rb")
                if f then
                    local chunk_size = 65536    -- 64KB per chunk
                    local max_scan = 2097152     -- max 2MB scan for POST body
                    local overlap = 2048        -- 2KB overlap for cross-chunk matching
                    local total = 0
                    local prev_tail = ""
                    local found = false

                    while total < max_scan and not found do
                        local chunk = f:read(chunk_size)
                        if not chunk then break end
                        total = total + #chunk

                        -- prepend previous tail for cross-chunk matching
                        local data = prev_tail .. chunk
                        -- recursive decode per chunk (catches multi-encoded attacks)
                        local decoded = recursive_unescape(data)

                        local matched = match_any_rule('post.rule', decoded, "joi")
                        if matched then
                            log_record('Deny_URL_POST', ngx.var.request_uri, "-", matched)
                            f:close()
                            if is_waf_enabled() == "on" then
                                waf_output()
                            end
                            return true
                        end

                        -- keep last 2KB as overlap for cross-chunk matching
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
            -- recursive decode (catches multi-encoded attacks)
            local decoded_body = recursive_unescape(body)
            local matched = match_any_rule('post.rule', decoded_body, "joi")
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
    -- per-location bypass: set $waf_enable off; in nginx location block
    if ngx.var.waf_enable == "off" then
        return
    end
    -- domain-level waf switch (cached per request)
    if is_waf_enabled() == "off" then
        return
    end
    if white_ip_check() then
    elseif dynamic_black_ip_check() then
    elseif white_url_check() then
    elseif black_ip_check() then
    elseif user_agent_attack_check() then
    elseif referer_check() then
    elseif cc_attack_check() then
    elseif cookie_attack_check() then
    elseif file_upload_check() then
    elseif url_attack_check() then
    elseif url_args_attack_check() then
    elseif post_attack_check() then
    else
        return
    end
end

--run NginxGuard, pcall to prevent 500 on any unexpected error (e.g. HTTP/2/HTTP/3)
local ok, err = pcall(waf_main)
if not ok then
    ngx.log(ngx.ERR, "waf_main error: ", err)
end
