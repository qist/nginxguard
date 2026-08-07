--waf core lib
require 'config'

--Get the client IP
function get_client_ip()
    CLIENT_IP = ngx.req.get_headers()["X_real_ip"]
    if CLIENT_IP == nil then
        CLIENT_IP = ngx.req.get_headers()["X_Forwarded_For"]
    end
    if CLIENT_IP == nil then
        CLIENT_IP  = ngx.var.remote_addr
    end
    if CLIENT_IP == nil then
        CLIENT_IP  = "unknown"
    end
    return CLIENT_IP
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
    local host = ngx.var.http_host
    if host == nil then
        host = ngx.var.server_name
    end
    if host == nil then
        return "default"
    end
    -- strip port: www.example.com:8080 -> www.example.com
    local domain = string.match(host, "^([^:]+)")
    if domain == nil then
        domain = host
    end
    return string.lower(domain)
end

--Get domain-level config (only the domain-specific overrides, no default merge)
--Returns nil if domain is not configured in domain.json → caller falls back to config.lua globals
--Result is cached per request via ngx.ctx
function get_domain_config()
    if ngx.ctx._domain_config_loaded then
        return ngx.ctx._domain_config
    end
    ngx.ctx._domain_config_loaded = true

    local cjson = require("cjson")
    local io = require 'io'
    local RULE_PATH = config_rule_dir
    local DOMAIN_FILE = io.open(RULE_PATH .. '/domain.json', "r")
    if DOMAIN_FILE == nil then
        ngx.ctx._domain_config = nil
        return nil
    end
    local content = DOMAIN_FILE:read("*a")
    DOMAIN_FILE:close()

    local ok, domain_config = pcall(cjson.decode, content)
    if not ok or type(domain_config) ~= "table" then
        ngx.ctx._domain_config = nil
        return nil
    end

    local domain = get_domain()

    -- exact domain match
    local specific = domain_config[domain]

    -- if no exact match, try wildcard patterns like *.example.com
    if specific == nil then
        for pattern, cfg in pairs(domain_config) do
            if pattern ~= "_comment" and type(cfg) == "table" then
                if string.find(pattern, "^%*%.") then
                    -- convert *.example.com -> ^.+\.example\.com$
                    local regex = string.gsub(pattern, "%%", "%%%%")
                    regex = string.gsub(regex, "%.", "%%.")
                    regex = string.gsub(regex, "^%*%%", "^.+")
                    regex = regex .. "$"
                    if ngx.re.find(domain, regex, "ijo") then
                        specific = cfg
                        break
                    end
                end
            end
        end
    end

    ngx.ctx._domain_config = specific
    return specific
end

--Get effective config value: domain-level first, fallback to global config_*
function get_effective_config(key)
    local dcfg = get_domain_config()
    if dcfg and dcfg[key] ~= nil then
        return dcfg[key]
    end
    return _G["config_" .. key]
end

--Read rule lines from a file, return table
local function read_rule_file(filepath)
    local io = require 'io'
    local f = io.open(filepath, "r")
    if f == nil then
        return nil
    end
    local t = {}
    for line in f:lines() do
        table.insert(t, line)
    end
    f:close()
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

--Get WAF rule (supports per-domain rule_dir override)
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
function log_record(method,url,data,ruletag)
    local cjson = require("cjson")
    local io = require 'io'
    local LOG_PATH = config_log_dir
    local CLIENT_IP = get_client_ip()
    local USER_AGENT = get_user_agent()
    local LOCAL_UTC = os.date("!*t",os.time());
    local LOCAL_TIME = os.time(LOCAL_UTC)
    local FORMAT_TIME = os.date("%Y-%m-%dT%H:%M:%SZ",LOCAL_TIME)
    local SERVER_NAME = ngx.var.server_name
    local LOCAL_TIME = ngx.localtime()
    local log_json_obj = {
                 ['@timestamp'] = FORMAT_TIME,
                 client_ip = CLIENT_IP,
                 local_time = LOCAL_TIME,
                 server_name = SERVER_NAME,
                 domain = get_domain(),
                 user_agent = USER_AGENT,
                 attack_method = method,
                 req_url = url,
                 req_data = data,
                 rule_tag = ruletag,
              }
    local LOG_LINE = cjson.encode(log_json_obj)
    local LOG_NAME = LOG_PATH..'/'..ngx.today().."_waf.log"
    local file = io.open(LOG_NAME,"a")
    if file == nil then
        return
    end
    file:write(LOG_LINE.."\n")
    file:flush()
    file:close()
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
