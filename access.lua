--WAF Action
require 'config'
require 'lib'

--args
local rulematch = ngx.re.find
local unescape = ngx.unescape_uri

--allow white ip
function white_ip_check()
     if get_effective_config("white_ip_check") == "on" then
        local IP_WHITE_RULE = get_rule('whiteip.rule')
        local WHITE_IP = get_client_ip()
        if IP_WHITE_RULE ~= nil then
            for _,rule in pairs(IP_WHITE_RULE) do
                if rule ~= "" and rulematch(WHITE_IP,glob_to_regex(rule),"jo") then
                    return true
                end
            end
        end
    end
end

--deny black ip (static blacklist from blackip.rule)
function black_ip_check()
     if get_effective_config("black_ip_check") == "on" then
        local IP_BLACK_RULE = get_rule('blackip.rule')
        local BLACK_IP = get_client_ip()
        if IP_BLACK_RULE ~= nil then
            for _,rule in pairs(IP_BLACK_RULE) do
                if rule ~= "" and rulematch(BLACK_IP,glob_to_regex(rule),"jo") then
                    log_record('BlackList_IP',ngx.var.request_uri,"_","_")
                    if get_effective_config("waf_enable") == "on" then
                        ngx.exit(403)
                        return true
                    end
                end
            end
        end
    end
end

--deny dynamic black ip (auto-banned by CC, with TTL auto-expire)
function dynamic_black_ip_check()
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
        if get_effective_config("waf_enable") == "on" then
            ngx.exit(403)
            return true
        end
    end
    return false
end

--allow white url
function white_url_check()
    if get_effective_config("white_url_check") == "on" then
        local URL_WHITE_RULES = get_rule('whiteurl.rule')
        local REQ_URI = ngx.var.request_uri
        if URL_WHITE_RULES ~= nil then
            for _,rule in pairs(URL_WHITE_RULES) do
                if rule ~= "" and rulematch(REQ_URI,rule,"jo") then
                    return true
                end
            end
        end
    end
end

--check if UA is whitelisted (search engine bots skip UA blacklist only)
local function is_white_ua()
    if get_effective_config("white_ua_check") == "on" then
        local UA_WHITE_RULES = get_rule('whiteua.rule')
        local USER_AGENT = ngx.var.http_user_agent
        if USER_AGENT ~= nil and UA_WHITE_RULES ~= nil then
            for _,rule in pairs(UA_WHITE_RULES) do
                if rule ~= "" and rulematch(USER_AGENT, rule, "ijo") then
                    return true
                end
            end
        end
    end
    return false
end

--deny cc attack (sliding window via incr + expire)
function cc_attack_check()
    if get_effective_config("cc_check") == "on" then
        local ATTACK_URI = ngx.var.uri
        local CC_TOKEN = get_client_ip() .. ATTACK_URI
        local limit = ngx.shared.limit
        if limit == nil then return false end
        local cc_rate = get_effective_config("cc_rate")
        local CCcount = tonumber(string.match(cc_rate, '(.*)/'))
        local CCseconds = tonumber(string.match(cc_rate, '/(.*)'))
        if CCcount == nil or CCseconds == nil then return false end

        -- incr with init: first request creates counter=1 with TTL, subsequent increments
        local count, err = limit:incr(CC_TOKEN, 1, 0, CCseconds)
        if count == nil then
            -- incr failed, try set as fallback
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
            if get_effective_config("waf_enable") == "on" then
                ngx.exit(403)
            end
            return true
        else
            -- refresh TTL on each request for sliding window effect
            -- expire() requires OpenResty 0.10.12+, pcall for older versions
            pcall(function() limit:expire(CC_TOKEN, CCseconds) end)
        end
    end
    return false
end

--deny cookie
function cookie_attack_check()
    if get_effective_config("cookie_check") == "on" then
        local COOKIE_RULES = get_rule('cookie.rule')
        local USER_COOKIE = ngx.var.http_cookie
        if USER_COOKIE ~= nil and COOKIE_RULES ~= nil then
            for _,rule in pairs(COOKIE_RULES) do
                if rule ~="" and rulematch(USER_COOKIE,rule,"jo") then
                    log_record('Deny_Cookie',ngx.var.request_uri,"-",rule)
                    if get_effective_config("waf_enable") == "on" then
                        waf_output()
                        return true
                    end
                end
             end
	 end
    end
    return false
end

--deny url
function url_attack_check()
    if get_effective_config("url_check") == "on" then
        local URL_RULES = get_rule('url.rule')
        local REQ_URI = ngx.var.request_uri
        if URL_RULES == nil then return false end
        for _,rule in pairs(URL_RULES) do
            if rule ~="" and rulematch(REQ_URI,rule,"jo") then
                log_record('Deny_URL',REQ_URI,"-",rule)
                if get_effective_config("waf_enable") == "on" then
                    waf_output()
                    return true
                end
            end
        end
    end
    return false
end

--deny url args
function url_args_attack_check()
    if get_effective_config("url_args_check") == "on" then
        local ARGS_RULES = get_rule('args.rule')
        if ARGS_RULES == nil then return false end
        local ok, REQ_ARGS = pcall(ngx.req.get_uri_args)
        if not ok or REQ_ARGS == nil then
            return false
        end
        for _,rule in pairs(ARGS_RULES) do
            for key, val in pairs(REQ_ARGS) do
                local ARGS_DATA
                if type(val) == 'table' then
                    ARGS_DATA = table.concat(val, " ")
                else
                    ARGS_DATA = val
                end
                if ARGS_DATA and type(ARGS_DATA) ~= "boolean" and rule ~= "" and rulematch(unescape(ARGS_DATA),rule,"jo") then
                    log_record('Deny_URL_Args',ngx.var.request_uri,"-",rule)
                    if get_effective_config("waf_enable") == "on" then
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
function user_agent_attack_check()
    if get_effective_config("user_agent_check") == "on" then
        if is_white_ua() then
            return false
        end
        local USER_AGENT_RULES = get_rule('useragent.rule')
        local USER_AGENT = ngx.var.http_user_agent
        if USER_AGENT ~= nil and USER_AGENT_RULES ~= nil then
            for _,rule in pairs(USER_AGENT_RULES) do
                if rule ~="" and rulematch(USER_AGENT,rule,"ijo") then
                    log_record('Deny_USER_AGENT',ngx.var.request_uri,"-",rule)
                    if get_effective_config("waf_enable") == "on" then
                        waf_output()
                        return true
                    end
                end
            end
        end
    end
    return false
end

--deny referer
function referer_check()
    if get_effective_config("referer_check") == "on" then
        local REFERER_RULES = get_rule('referer.rule')
        local REFERER = ngx.var.http_referer
        if REFERER ~= nil and REFERER_RULES ~= nil then
            for _,rule in pairs(REFERER_RULES) do
                if rule ~= "" and rulematch(REFERER, rule, "jo") then
                    log_record('Deny_Referer', ngx.var.request_uri, "-", rule)
                    if get_effective_config("waf_enable") == "on" then
                        waf_output()
                        return true
                    end
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
function file_upload_check()
    if get_effective_config("file_upload_check") == "on" then
        local UPLOAD_RULES = get_rule('fileext.rule')
        if UPLOAD_RULES == nil then return false end
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

        -- match each filename against rules individually
        for _, fname in ipairs(filenames) do
            for _, rule in pairs(UPLOAD_RULES) do
                if rule ~= "" and rulematch(fname, rule, "jo") then
                    log_record('Deny_File_Upload', ngx.var.request_uri, "-", rule)
                    if get_effective_config("waf_enable") == "on" then
                        waf_output()
                        return true
                    end
                end
            end
        end
    end
    return false
end

--deny post (form + JSON body)
function post_attack_check()
    if get_effective_config("post_check") == "on" then
        -- skip non-POST/PUT requests (fix HTTP/2 GET 500 error)
        local METHOD = ngx.req.get_method()
        if METHOD ~= "POST" and METHOD ~= "PUT" and METHOD ~= "PATCH" then
            return false
        end
        local POST_RULES = get_rule('post.rule')
        if POST_RULES == nil then return false end

        -- read body first, pcall to prevent HTTP/2/HTTP/3 errors
        local ok = pcall(ngx.req.read_body)
        if not ok then
            return false
        end

        -- 1. Try form-encoded args
        local ok2, POST_ARGS = pcall(ngx.req.get_post_args)
        if ok2 and POST_ARGS ~= nil then
            for _,rule in pairs(POST_RULES) do
                for key, val in pairs(POST_ARGS) do
                    local POST_DATA
                    if type(val) == 'table' then
                        POST_DATA = table.concat(val, " ")
                    else
                        POST_DATA = val
                    end
                    if POST_DATA and type(POST_DATA) ~= "boolean" and rule ~= "" and rulematch(POST_DATA, rule, "jo") then
                        log_record('Deny_URL_POST', ngx.var.request_body, "-", rule)
                        if get_effective_config("waf_enable") == "on" then
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
            -- body too large, stored in temp file
            local file = ngx.req.get_body_file()
            if file then
                local f = io.open(file, "r")
                if f then body = f:read("*a") f:close() end
            end
        end
        if body and #body > 0 then
            for _,rule in pairs(POST_RULES) do
                if rule ~= "" and rulematch(unescape(body), rule, "jo") then
                    log_record('Deny_URL_POST', ngx.var.request_uri, "-", rule)
                    if get_effective_config("waf_enable") == "on" then
                        waf_output()
                        return true
                    end
                end
            end
        end
    end
    return false
end

--WAF main entry
function waf_main()
    -- domain-level waf switch
    if get_effective_config("waf_enable") == "off" then
        return
    end
    if white_ip_check() then
    elseif white_url_check() then
    elseif dynamic_black_ip_check() then
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

--run WAF, pcall to prevent 500 on any unexpected error (e.g. HTTP/2/HTTP/3)
local ok, err = pcall(waf_main)
if not ok then
    ngx.log(ngx.ERR, "waf_main error: ", err)
end
