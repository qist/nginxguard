#!/bin/bash
# 安全版：不修改 lib.lua，而是创建一个独立的调试 access lua 文件
# 通过临时替换 access_by_lua_file 来注入性能打点

WAF_CONFIG="/opt/nginx/lua/waf/config.lua"
RULE_DIR="/opt/nginx/lua/waf/rule-config"
NGINX_CONF="/opt/nginx/conf/nginx.conf"
RESULT_FILE="/tmp/bench_debug_v2.txt"
> $RESULT_FILE

cp $WAF_CONFIG ${WAF_CONFIG}.bak_d2
cp $NGINX_CONF ${NGINX_CONF}.bak_d2

# 关闭 CC 避免干扰
sed -i 's|^config_cc_check = .*|config_cc_check = "off"|' $WAF_CONFIG
sed -i 's|^config_trust_proxy_headers = .*|config_trust_proxy_headers = "on"|' $WAF_CONFIG

# 创建调试版 access_by_lua_file
cat > /opt/nginx/lua/waf/access_debug.lua << 'LUAEOF'
-- access_debug.lua: 性能打点版 access.lua
require 'config'
require 'lib'

local function waf_main_debug()
    local t = {}
    t.t0 = ngx.now()

    if ngx.var.waf_enable == "off" then return end
    if get_effective_config("waf_enable") == "off" then return end

    -- IP checks
    t.t1 = ngx.now()
    local ip = get_client_ip()
    t.t2 = ngx.now()

    -- white_ip_check
    if get_effective_config("white_ip_check") == "on" then
        match_ip_rule('whiteip.rule', ip)
    end
    t.t3 = ngx.now()

    -- dynamic_black_ip_check
    local badGuys = ngx.shared.badGuys
    if badGuys and badGuys:get(ip) then
        ngx.exit(403)
        return
    end
    t.t4 = ngx.now()

    -- black_ip_check
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
            if entry.combined then
                ngx.re.find(REQ_URI, entry.combined, "joi")
            end
        end
    end
    t.t6 = ngx.now()

    -- user_agent_check
    if get_effective_config("user_agent_check") == "on" then
        local USER_AGENT = ngx.var.http_user_agent
        if USER_AGENT then
            local entry = get_rule_entry('useragent.rule')
            if entry and not entry.empty then
                if entry.fast_hash then
                    for _, rule in ipairs(entry.fast_rules) do
                        if string.find(USER_AGENT, rule, 1, true) then break end
                    end
                end
                if entry.combined then
                    ngx.re.find(USER_AGENT, entry.combined, "ijo")
                end
            end
        end
    end
    t.t7 = ngx.now()

    -- url_check
    if get_effective_config("url_check") == "on" then
        local REQ_URI = ngx.var.request_uri
        match_any_rule('url.rule', REQ_URI, "joi")
    end
    t.t8 = ngx.now()

    -- url_args_check
    if get_effective_config("url_args_check") == "on" then
        local ok, REQ_ARGS = pcall(ngx.req.get_uri_args)
        if ok and REQ_ARGS then
            for key, val in pairs(REQ_ARGS) do
                local ARGS_DATA
                if type(val) == 'table' then ARGS_DATA = table.concat(val, " ")
                else ARGS_DATA = val end
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
        if USER_COOKIE then
            match_any_rule('cookie.rule', USER_COOKIE, "joi")
        end
    end
    t.t10 = ngx.now()

    -- 总耗时
    local total = t.t10 - t.t0
    local gc_ip = t.t2 - t.t1
    local white_ip = t.t3 - t.t2
    local dyn_black = t.t4 - t.t3
    local black_ip = t.t5 - t.t4
    local white_url = t.t6 - t.t5
    local ua_check = t.t7 - t.t6
    local url_check = t.t8 - t.t7
    local args_check = t.t9 - t.t8
    local cookie_check = t.t10 - t.t9

    -- 只在前5个请求打日志
    if not ngx.shared.limit:get("debug_access_count") then
        ngx.shared.limit:set("debug_access_count", 1, 60)
        ngx.log(ngx.NOTICE, string.format(
            "[BENCH_ACCESS] total=%.4fms | get_client_ip=%.4fms white_ip=%.4fms dyn_black=%.4fms black_ip=%.4fms white_url=%.4fms ua=%.4fms url=%.4fms args=%.4fms cookie=%.4fms | ip=%s",
            total*1000, gc_ip*1000, white_ip*1000, dyn_black*1000, black_ip*1000,
            white_url*1000, ua_check*1000, url_check*1000, args_check*1000, cookie_check*1000,
            ip
        ))
    end
end

local ok, err = pcall(waf_main_debug)
if not ok then
    ngx.log(ngx.ERR, "waf_debug error: ", err)
end
LUAEOF

# 替换 nginx.conf 中的 access_by_lua_file
sed -i 's|access_by_lua_file "/apps/nginx/conf/waf/access.lua"|access_by_lua_file "/apps/nginx/conf/waf/access_debug.lua"|' $NGINX_CONF
sed -i 's|access_by_lua_file ".*access.lua"|access_by_lua_file "/opt/nginx/lua/waf/access_debug.lua"|' $NGINX_CONF

# 重启 nginx
kill -TERM $(cat /opt/nginx/logs/nginx.pid) 2>/dev/null; sleep 2
cd /opt/nginx && ./nginx -p /opt/nginx/ -c conf/nginx.conf 2>&1; sleep 2

echo "===== 发送请求触发性能打点 =====" | tee -a $RESULT_FILE
for i in $(seq 1 3); do
    curl -s -o /dev/null -w "HTTP %{http_code}\n" -H "User-Agent: Mozilla/5.0" http://127.0.0.1/
done
for i in $(seq 1 3); do
    curl -s -o /dev/null -w "HTTP %{http_code}\n" -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 1.2.3.4" http://127.0.0.1/
done

echo "" | tee -a $RESULT_FILE
echo "===== error.log 中的 BENCH_ACCESS 日志 =====" | tee -a $RESULT_FILE
tail -30 /opt/nginx/logs/error.log 2>/dev/null | grep "BENCH_ACCESS" | tee -a $RESULT_FILE

echo "" | tee -a $RESULT_FILE
echo "===== ab 压测对比 =====" | tee -a $RESULT_FILE
echo "--- 不带 XFF (3次取最佳) ---" | tee -a $RESULT_FILE
best=0
for i in 1 2 3; do
    rps=$(ab -n 10000 -c 100 -k -H "User-Agent: Mozilla/5.0" http://127.0.0.1/ 2>&1 | grep "Requests per second" | awk '{print $4}')
    echo "  Run $i: RPS=$rps" | tee -a $RESULT_FILE
    result=$(echo "$rps > $best" | bc 2>/dev/null)
    if [ "$result" = "1" -o $i -eq 1 ]; then best=$rps; fi
done
echo "  BEST noXFF: $rps" | tee -a $RESULT_FILE

echo "--- 带 XFF (3次取最佳) ---" | tee -a $RESULT_FILE
best=0
for i in 1 2 3; do
    rps=$(ab -n 10000 -c 100 -k -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 1.2.3.4" http://127.0.0.1/ 2>&1 | grep "Requests per second" | awk '{print $4}')
    echo "  Run $i: RPS=$rps" | tee -a $RESULT_FILE
    result=$(echo "$rps > $best" | bc 2>/dev/null)
    if [ "$result" = "1" -o $i -eq 1 ]; then best=$rps; fi
done
echo "  BEST withXFF: $rps" | tee -a $RESULT_FILE

# 恢复
cp ${NGINX_CONF}.bak_d2 $NGINX_CONF
cp ${WAF_CONFIG}.bak_d2 $WAF_CONFIG
rm -f /opt/nginx/lua/waf/access_debug.lua ${NGINX_CONF}.bak_d2 ${WAF_CONFIG}.bak_d2
kill -TERM $(cat /opt/nginx/logs/nginx.pid) 2>/dev/null; sleep 2
./nginx -p /opt/nginx/ -c conf/nginx.conf 2>&1; sleep 2
echo "===== 恢复完成 =====" | tee -a $RESULT_FILE
