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

--deny cc attack
function cc_attack_check()
    if get_effective_config("cc_check") == "on" then
        local ATTACK_URI=ngx.var.uri
        local CC_TOKEN = get_client_ip()..ATTACK_URI
        local limit = ngx.shared.limit
        local cc_rate = get_effective_config("cc_rate")
        local CCcount=tonumber(string.match(cc_rate,'(.*)/'))
        local CCseconds=tonumber(string.match(cc_rate,'/(.*)'))
        local req,_ = limit:get(CC_TOKEN)
        if req then
            if req > CCcount then
                log_record('CC_Attack',ngx.var.request_uri,"-","-")
                -- auto-ban IP with TTL
                local block_ttl = tonumber(get_effective_config("cc_block_ttl"))
                if block_ttl and block_ttl > 0 then
                    local badGuys = ngx.shared.badGuys
                    if badGuys and not badGuys:get(get_client_ip()) then
                        badGuys:set(get_client_ip(), 1, block_ttl)
                        log_record('CC_AutoBan',ngx.var.request_uri,"_","ban_"..block_ttl.."s")
                    end
                end
                if get_effective_config("waf_enable") == "on" then
                    ngx.exit(403)
                end
            else
                limit:incr(CC_TOKEN,1)
            end
        else
            limit:set(CC_TOKEN,1,CCseconds)
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
        local ok, REQ_ARGS = pcall(ngx.req.get_uri_args)
        if not ok or REQ_ARGS == nil or ARGS_RULES == nil then
            return false
        end
        for _,rule in pairs(ARGS_RULES) do
            for key, val in pairs(REQ_ARGS) do
                if type(val) == 'table' then
                local ARGS_DATA = table.concat(val, " ")
                else
                    local ARGS_DATA = val
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

--deny user agent
function user_agent_attack_check()
    if get_effective_config("user_agent_check") == "on" then
        local USER_AGENT_RULES = get_rule('useragent.rule')
        local USER_AGENT = ngx.var.http_user_agent
        if USER_AGENT ~= nil and USER_AGENT_RULES ~= nil then
            for _,rule in pairs(USER_AGENT_RULES) do
                if rule ~="" and rulematch(USER_AGENT,rule,"jo") then
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

--deny post
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
        local ok2, POST_ARGS = pcall(ngx.req.get_post_args)
        if not ok2 or POST_ARGS == nil then
            return false
        end
        for _,rule in pairs(POST_RULES) do
            for key, val in pairs(POST_ARGS) do
                if type(val) == 'table' then
                    local POST_DATA = table.concat(val, " ")
                else
                    local POST_DATA = val
                end
                if POST_DATA and type(POST_DATA) ~= "boolean" and rule ~="" and rulematch(unescape(POST_DATA),rule,"jo") then
                    log_record('Deny_URL_POST',ngx.var.request_body,"-",rule)
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
    elseif cc_attack_check() then
    elseif cookie_attack_check() then
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
