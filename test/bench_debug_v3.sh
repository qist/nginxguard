#!/bin/bash
# 安全版 v3: 正确替换 access_by_lua_file 路径

WAF_CONFIG="/opt/nginx/lua/waf/config.lua"
NGINX_CONF="/opt/nginx/conf/nginx.conf"
RESULT_FILE="/tmp/bench_debug_v3.txt"
> $RESULT_FILE

cp $WAF_CONFIG ${WAF_CONFIG}.bak_d3
cp $NGINX_CONF ${NGINX_CONF}.bak_d3

sed -i 's|^config_cc_check = .*|config_cc_check = "off"|' $WAF_CONFIG
sed -i 's|^config_trust_proxy_headers = .*|config_trust_proxy_headers = "on"|' $WAF_CONFIG

# 创建调试版
cat > /opt/nginx/lua/waf/access_debug.lua << 'LUAEOF'
require 'config'
require 'lib'

local function waf_main_debug()
    local t = {}
    t.t0 = ngx.now()
    if ngx.var.waf_enable == "off" then return end
    if get_effective_config("waf_enable") == "off" then return end

    t.t1 = ngx.now()
    local ip = get_client_ip()
    t.t2 = ngx.now()

    if get_effective_config("white_ip_check") == "on" then
        match_ip_rule('whiteip.rule', ip)
    end
    t.t3 = ngx.now()

    local badGuys = ngx.shared.badGuys
    if badGuys and badGuys:get(ip) then ngx.exit(403) return end
    t.t4 = ngx.now()

    if get_effective_config("black_ip_check") == "on" then
        match_ip_rule('blackip.rule', ip)
    end
    t.t5 = ngx.now()

    -- white_url_check
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
    t.t6 = ngx.now()

    -- user_agent_check (含 white_ua)
    if get_effective_config("user_agent_check") == "on" then
        local USER_AGENT = ngx.var.http_user_agent
        if USER_AGENT then
            -- white UA check
            if get_effective_config("white_ua_check") == "on" then
                local entry = get_rule_entry('whiteua.rule')
                if entry and not entry.empty then
                    if entry.fast_hash then
                        for _, rule in ipairs(entry.fast_rules) do
                            if string.find(USER_AGENT, rule, 1, true) then break end
                        end
                    end
                end
            end
            -- ua blacklist
            match_any_rule('useragent.rule', USER_AGENT, "ijo")
        end
    end
    t.t7 = ngx.now()

    -- url_check
    if get_effective_config("url_check") == "on" then
        match_any_rule('url.rule', ngx.var.request_uri, "joi")
    end
    t.t8 = ngx.now()

    -- url_args_check
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
    t.t9 = ngx.now()

    -- cookie_check
    if get_effective_config("cookie_check") == "on" then
        local USER_COOKIE = ngx.var.http_cookie
        if USER_COOKIE then match_any_rule('cookie.rule', USER_COOKIE, "joi") end
    end
    t.t10 = ngx.now()

    local total = t.t10 - t.t0
    -- 只在前3个请求打日志
    if not ngx.shared.limit:get("dbg_cnt") then
        ngx.shared.limit:set("dbg_cnt", 1, 60)
        ngx.log(ngx.NOTICE, string.format(
            "[BENCH] total=%.3fms | client_ip=%.3fms white_ip=%.3fms dyn_black=%.3fms black_ip=%.3fms white_url=%.3fms ua=%.3fms url=%.3fms args=%.3fms cookie=%.3fms | ip=%s xff=%s",
            total*1000,
            (t.t2-t.t1)*1000, (t.t3-t.t2)*1000, (t.t4-t.t3)*1000, (t.t5-t.t4)*1000,
            (t.t6-t.t5)*1000, (t.t7-t.t6)*1000, (t.t8-t.t7)*1000, (t.t9-t.t8)*1000, (t.t10-t.t9)*1000,
            ip, tostring(ngx.var.http_x_forwarded_for)
        ))
    end
end

local ok, err = pcall(waf_main_debug)
if not ok then ngx.log(ngx.ERR, "debug error: ", err) end
LUAEOF

# 替换 nginx.conf
sed -i 's|access_by_lua_file "lua/waf/access.lua"|access_by_lua_file "lua/waf/access_debug.lua"|' $NGINX_CONF

# 重启
kill -TERM $(cat /opt/nginx/logs/nginx.pid) 2>/dev/null; sleep 2
cd /opt/nginx && ./nginx -p /opt/nginx/ -c conf/nginx.conf 2>&1; sleep 2

echo "===== 发送请求 =====" | tee -a $RESULT_FILE
curl -s -o /dev/null -w "HTTP %{http_code}\n" -H "User-Agent: Mozilla/5.0" http://127.0.0.1/
curl -s -o /dev/null -w "HTTP %{http_code}\n" -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 1.2.3.4" http://127.0.0.1/

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
cp ${NGINX_CONF}.bak_d3 $NGINX_CONF
cp ${WAF_CONFIG}.bak_d3 $WAF_CONFIG
rm -f /opt/nginx/lua/waf/access_debug.lua ${NGINX_CONF}.bak_d3 ${WAF_CONFIG}.bak_d3
kill -TERM $(cat /opt/nginx/logs/nginx.pid) 2>/dev/null; sleep 2
./nginx -p /opt/nginx/ -c conf/nginx.conf 2>&1; sleep 2
echo "===== 恢复完成 =====" | tee -a $RESULT_FILE
