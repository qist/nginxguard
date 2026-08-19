#!/bin/bash
# v4: 用 ngx.ERR 打日志 (error_log 默认级别就能看到)
WAF_CONFIG="/opt/nginx/lua/waf/config.lua"
NGINX_CONF="/opt/nginx/conf/nginx.conf"
RESULT_FILE="/tmp/bench_debug_v4.txt"
> $RESULT_FILE

cp $WAF_CONFIG ${WAF_CONFIG}.bak_d4
cp $NGINX_CONF ${NGINX_CONF}.bak_d4

sed -i 's|^config_cc_check = .*|config_cc_check = "off"|' $WAF_CONFIG
sed -i 's|^config_trust_proxy_headers = .*|config_trust_proxy_headers = "on"|' $WAF_CONFIG

cat > /opt/nginx/lua/waf/access_debug.lua << 'LUAEOF'
require 'config'
require 'lib'

local function waf_main_debug()
    local t0 = ngx.now()
    if ngx.var.waf_enable == "off" then return end
    if get_effective_config("waf_enable") == "off" then return end

    local t1 = ngx.now()
    local ip = get_client_ip()
    local t2 = ngx.now()

    local t_wip_s = ngx.now()
    if get_effective_config("white_ip_check") == "on" then
        match_ip_rule('whiteip.rule', ip)
    end
    local t_wip_e = ngx.now()

    local t_dblk_s = ngx.now()
    local badGuys = ngx.shared.badGuys
    if badGuys and badGuys:get(ip) then ngx.exit(403) return end
    local t_dblk_e = ngx.now()

    local t_bip_s = ngx.now()
    if get_effective_config("black_ip_check") == "on" then
        match_ip_rule('blackip.rule', ip)
    end
    local t_bip_e = ngx.now()

    local t_wurl_s = ngx.now()
    if get_effective_config("white_url_check") == "on" then
        local entry = get_rule_entry('whiteurl.rule')
        if entry and not entry.empty then
            local REQ_URI = ngx.var.request_uri
            if entry.fast_hash then
                for _, rule in ipairs(entry.fast_rules) do
                    if string.find(REQ_URI, rule, 1, true) then break end
                end
            end
            if entry.combined then ngx.re.find(REQ_URI, entry.combined, "joi") end
        end
    end
    local t_wurl_e = ngx.now()

    local t_ua_s = ngx.now()
    if get_effective_config("user_agent_check") == "on" then
        local USER_AGENT = ngx.var.http_user_agent
        if USER_AGENT then
            if get_effective_config("white_ua_check") == "on" then
                local entry = get_rule_entry('whiteua.rule')
                if entry and not entry.empty and entry.fast_hash then
                    for _, rule in ipairs(entry.fast_rules) do
                        if string.find(USER_AGENT, rule, 1, true) then break end
                    end
                end
            end
            match_any_rule('useragent.rule', USER_AGENT, "ijo")
        end
    end
    local t_ua_e = ngx.now()

    local t_url_s = ngx.now()
    if get_effective_config("url_check") == "on" then
        match_any_rule('url.rule', ngx.var.request_uri, "joi")
    end
    local t_url_e = ngx.now()

    local t_args_s = ngx.now()
    if get_effective_config("url_args_check") == "on" then
        local ok, REQ_ARGS = pcall(ngx.req.get_uri_args)
        if ok and REQ_ARGS then
            for key, val in pairs(REQ_ARGS) do
                local ARGS_DATA = type(val) == 'table' and table.concat(val, " ") or val
                if ARGS_DATA and type(ARGS_DATA) ~= "boolean" then
                    match_any_rule('args.rule', ARGS_DATA, "joi")
                end
            end
        end
    end
    local t_args_e = ngx.now()

    local t_cookie_s = ngx.now()
    if get_effective_config("cookie_check") == "on" then
        local USER_COOKIE = ngx.var.http_cookie
        if USER_COOKIE then match_any_rule('cookie.rule', USER_COOKIE, "joi") end
    end
    local t_cookie_e = ngx.now()

    local t_end = ngx.now()

    -- 用 ERR 级别确保日志输出
    if not ngx.shared.limit:get("dbg4") then
        ngx.shared.limit:set("dbg4", 1, 60)
        ngx.log(ngx.ERR, string.format(
            "[BENCH] total=%.3fms | client_ip=%.3fms white_ip=%.3fms dyn_black=%.3fms black_ip=%.3fms white_url=%.3fms ua=%.3fms url=%.3fms args=%.3fms cookie=%.3fms | ip=%s xff=%s",
            (t_end-t0)*1000,
            (t2-t1)*1000, (t_wip_e-t_wip_s)*1000, (t_dblk_e-t_dblk_s)*1000, (t_bip_e-t_bip_s)*1000,
            (t_wurl_e-t_wurl_s)*1000, (t_ua_e-t_ua_s)*1000, (t_url_e-t_url_s)*1000, (t_args_e-t_args_s)*1000, (t_cookie_e-t_cookie_s)*1000,
            ip, tostring(ngx.var.http_x_forwarded_for)
        ))
    end
end

local ok, err = pcall(waf_main_debug)
if not ok then ngx.log(ngx.ERR, "debug error: ", err) end
LUAEOF

sed -i 's|access_by_lua_file "lua/waf/access.lua"|access_by_lua_file "lua/waf/access_debug.lua"|' $NGINX_CONF

kill -TERM $(cat /opt/nginx/logs/nginx.pid) 2>/dev/null; sleep 2
cd /opt/nginx && ./nginx -p /opt/nginx/ -c conf/nginx.conf 2>&1; sleep 2

echo "===== 发送请求 =====" | tee -a $RESULT_FILE
curl -s -o /dev/null -w "HTTP %{http_code} noXFF\n" -H "User-Agent: Mozilla/5.0" http://127.0.0.1/
curl -s -o /dev/null -w "HTTP %{http_code} withXFF\n" -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 1.2.3.4" http://127.0.0.1/

echo "" | tee -a $RESULT_FILE
echo "===== BENCH 日志 =====" | tee -a $RESULT_FILE
grep "BENCH" /opt/nginx/log/error.log 2>/dev/null | tail -5 | tee -a $RESULT_FILE

echo "" | tee -a $RESULT_FILE
echo "===== ab 压测 =====" | tee -a $RESULT_FILE
echo "--- 不带 XFF ---" | tee -a $RESULT_FILE
ab -n 10000 -c 100 -k -H "User-Agent: Mozilla/5.0" http://127.0.0.1/ 2>&1 | grep -E "Requests per second|Time per request.*mean" | tee -a $RESULT_FILE
echo "--- 带 XFF ---" | tee -a $RESULT_FILE
ab -n 10000 -c 100 -k -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 1.2.3.4" http://127.0.0.1/ 2>&1 | grep -E "Requests per second|Time per request.*mean" | tee -a $RESULT_FILE

# 恢复
cp ${NGINX_CONF}.bak_d4 $NGINX_CONF
cp ${WAF_CONFIG}.bak_d4 $WAF_CONFIG
rm -f /opt/nginx/lua/waf/access_debug.lua ${NGINX_CONF}.bak_d4 ${WAF_CONFIG}.bak_d4
kill -TERM $(cat /opt/nginx/logs/nginx.pid) 2>/dev/null; sleep 2
./nginx -p /opt/nginx/ -c conf/nginx.conf 2>&1; sleep 2
echo "===== 恢复完成 =====" | tee -a $RESULT_FILE
