#!/bin/bash
# v6: 直接在远程执行，手动检查每步
WAF_CONFIG="/opt/nginx/lua/waf/config.lua"
NGINX_CONF="/opt/nginx/conf/nginx.conf"

cp $WAF_CONFIG ${WAF_CONFIG}.bak_d6
cp $NGINX_CONF ${NGINX_CONF}.bak_d6

sed -i 's|^config_cc_check = .*|config_cc_check = "off"|' $WAF_CONFIG
sed -i 's|^config_trust_proxy_headers = .*|config_trust_proxy_headers = "on"|' $WAF_CONFIG

cat > /opt/nginx/lua/waf/access_debug.lua << 'LUAEOF'
require 'config'
require 'lib'

local count = 0
local total_cip = 0
local total_all = 0
local total_wip = 0
local total_bip = 0
local total_wurl = 0
local total_ua = 0
local total_url = 0
local total_args = 0
local total_cookie = 0

local function waf_main_debug()
    if ngx.var.waf_enable == "off" then return end
    if get_effective_config("waf_enable") == "off" then return end

    local t0 = ngx.now()
    local t1 = ngx.now()
    local ip = get_client_ip()
    local t2 = ngx.now()

    local t3 = ngx.now()
    if get_effective_config("white_ip_check") == "on" then match_ip_rule('whiteip.rule', ip) end
    local t4 = ngx.now()

    local t5 = ngx.now()
    local badGuys = ngx.shared.badGuys
    if badGuys and badGuys:get(ip) then ngx.exit(403) return end
    local t6 = ngx.now()

    local t7 = ngx.now()
    if get_effective_config("black_ip_check") == "on" then match_ip_rule('blackip.rule', ip) end
    local t8 = ngx.now()

    local t9 = ngx.now()
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
    local t10 = ngx.now()

    local t11 = ngx.now()
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
    local t12 = ngx.now()

    local t13 = ngx.now()
    if get_effective_config("url_check") == "on" then
        match_any_rule('url.rule', ngx.var.request_uri, "joi")
    end
    local t14 = ngx.now()

    local t15 = ngx.now()
    if get_effective_config("url_args_check") == "on" then
        local ok, REQ_ARGS = pcall(ngx.req.get_uri_args)
        if ok and REQ_ARGS then
            for _, val in pairs(REQ_ARGS) do
                local ARGS_DATA = type(val) == 'table' and table.concat(val, " ") or val
                if ARGS_DATA and type(ARGS_DATA) ~= "boolean" then
                    match_any_rule('args.rule', ARGS_DATA, "joi")
                end
            end
        end
    end
    local t16 = ngx.now()

    local t17 = ngx.now()
    if get_effective_config("cookie_check") == "on" then
        local USER_COOKIE = ngx.var.http_cookie
        if USER_COOKIE then match_any_rule('cookie.rule', USER_COOKIE, "joi") end
    end
    local t18 = ngx.now()

    count = count + 1
    total_cip = total_cip + (t2 - t1)
    total_wip = total_wip + (t4 - t3)
    total_bip = total_bip + (t8 - t7)
    total_wurl = total_wurl + (t10 - t9)
    total_ua = total_ua + (t12 - t11)
    total_url = total_url + (t14 - t13)
    total_args = total_args + (t16 - t15)
    total_cookie = total_cookie + (t18 - t17)
    total_all = total_all + (t18 - t0)

    if count % 200 == 0 then
        ngx.log(ngx.ERR, string.format(
            "[BENCH6] n=%d cip=%.3fms wip=%.3fms bip=%.3fms wurl=%.3fms ua=%.3fms url=%.3fms args=%.3fms cookie=%.3fms total=%.3fms",
            count, total_cip*1000, total_wip*1000, total_bip*1000, total_wurl*1000,
            total_ua*1000, total_url*1000, total_args*1000, total_cookie*1000, total_all*1000
        ))
    end
end

local ok, err = pcall(waf_main_debug)
if not ok then ngx.log(ngx.ERR, "debug6 error: ", err) end
LUAEOF

# 检查 sed 是否成功
echo "Before sed:"
grep 'access_by_lua_file' $NGINX_CONF
sed -i 's|access_by_lua_file "lua/waf/access.lua"|access_by_lua_file "lua/waf/access_debug.lua"|' $NGINX_CONF
echo "After sed:"
grep 'access_by_lua_file' $NGINX_CONF

kill -TERM $(cat /opt/nginx/logs/nginx.pid) 2>/dev/null; sleep 2
cd /opt/nginx && ./nginx -p /opt/nginx/ -c conf/nginx.conf 2>&1; sleep 2

echo "===== 预热 + 压测 不带 XFF ====="
ab -n 1000 -c 50 -k -H "User-Agent: Mozilla/5.0" http://127.0.0.1/ >/dev/null 2>&1
# 清除旧日志
grep -v "BENCH6" /opt/nginx/log/error.log > /tmp/err_before.txt 2>/dev/null
ab -n 10000 -c 100 -k -H "User-Agent: Mozilla/5.0" http://127.0.0.1/ 2>&1 | grep -E "Requests per second|Time per request.*mean"
echo "--- BENCH6 日志 ---"
grep "BENCH6" /opt/nginx/log/error.log | tail -5

echo ""
echo "===== 预热 + 压测 带 XFF ====="
ab -n 1000 -c 50 -k -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 1.2.3.4" http://127.0.0.1/ >/dev/null 2>&1
grep -v "BENCH6" /opt/nginx/log/error.log > /tmp/err_before2.txt 2>/dev/null
ab -n 10000 -c 100 -k -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 1.2.3.4" http://127.0.0.1/ 2>&1 | grep -E "Requests per second|Time per request.*mean"
echo "--- BENCH6 日志 (XFF) ---"
grep "BENCH6" /opt/nginx/log/error.log | grep -v -f /tmp/err_before2.txt 2>/dev/null | tail -5

# 恢复
cp ${NGINX_CONF}.bak_d6 $NGINX_CONF
cp ${WAF_CONFIG}.bak_d6 $WAF_CONFIG
rm -f /opt/nginx/lua/waf/access_debug.lua ${NGINX_CONF}.bak_d6 ${WAF_CONFIG}.bak_d6
kill -TERM $(cat /opt/nginx/logs/nginx.pid) 2>/dev/null; sleep 2
./nginx -p /opt/nginx/ -c conf/nginx.conf 2>&1; sleep 2
echo "===== 恢复完成 ====="
