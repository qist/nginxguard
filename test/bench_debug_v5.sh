#!/bin/bash
# v5: 累加多次请求耗时，统计平均值
WAF_CONFIG="/opt/nginx/lua/waf/config.lua"
NGINX_CONF="/opt/nginx/conf/nginx.conf"
RESULT_FILE="/tmp/bench_debug_v5.txt"
> $RESULT_FILE

cp $WAF_CONFIG ${WAF_CONFIG}.bak_d5
cp $NGINX_CONF ${NGINX_CONF}.bak_d5

sed -i 's|^config_cc_check = .*|config_cc_check = "off"|' $WAF_CONFIG
sed -i 's|^config_trust_proxy_headers = .*|config_trust_proxy_headers = "on"|' $WAF_CONFIG

cat > /opt/nginx/lua/waf/access_debug.lua << 'LUAEOF'
require 'config'
require 'lib'

-- worker 级别累加
local _count = 0
local _total_t = 0
local _cip_t = 0
local _wip_t = 0
local _dblk_t = 0
local _bip_t = 0
local _wurl_t = 0
local _ua_t = 0
local _url_t = 0
local _args_t = 0
local _cookie_t = 0

local function waf_main_debug()
    local t0 = ngx.now()
    if ngx.var.waf_enable == "off" then return end
    if get_effective_config("waf_enable") == "off" then return end

    local t1 = ngx.now()
    local ip = get_client_ip()
    local t2 = ngx.now()

    local tws = ngx.now()
    if get_effective_config("white_ip_check") == "on" then
        match_ip_rule('whiteip.rule', ip)
    end
    local twe = ngx.now()

    local tds = ngx.now()
    local badGuys = ngx.shared.badGuys
    if badGuys and badGuys:get(ip) then ngx.exit(403) return end
    local tde = ngx.now()

    local tbs = ngx.now()
    if get_effective_config("black_ip_check") == "on" then
        match_ip_rule('blackip.rule', ip)
    end
    local tbe = ngx.now()

    local twus = ngx.now()
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
    local twue = ngx.now()

    local tuas = ngx.now()
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
    local tuae = ngx.now()

    local turls = ngx.now()
    if get_effective_config("url_check") == "on" then
        match_any_rule('url.rule', ngx.var.request_uri, "joi")
    end
    local turle = ngx.now()

    local targs = ngx.now()
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
    local targse = ngx.now()

    local tcs = ngx.now()
    if get_effective_config("cookie_check") == "on" then
        local USER_COOKIE = ngx.var.http_cookie
        if USER_COOKIE then match_any_rule('cookie.rule', USER_COOKIE, "joi") end
    end
    local tce = ngx.now()

    local tend = ngx.now()

    -- 累加
    _count = _count + 1
    _total_t = _total_t + (tend - t0)
    _cip_t = _cip_t + (t2 - t1)
    _wip_t = _wip_t + (twe - tws)
    _dblk_t = _dblk_t + (tde - tds)
    _bip_t = _bip_t + (tbe - tbs)
    _wurl_t = _wurl_t + (twue - twus)
    _ua_t = _ua_t + (tuae - tuas)
    _url_t = _url_t + (turle - turls)
    _args_t = _args_t + (targse - targs)
    _cookie_t = _cookie_t + (tce - tcs)

    -- 每 500 个请求输出一次汇总
    if _count % 500 == 0 then
        ngx.log(ngx.ERR, string.format(
            "[BENCH] n=%d | total=%.2fms avg=%.4fms | client_ip=%.2fms(%.1f%%) white_ip=%.2fms(%.1f%%) dyn_black=%.2fms(%.1f%%) black_ip=%.2fms(%.1f%%) white_url=%.2fms(%.1f%%) ua=%.2fms(%.1f%%) url=%.2fms(%.1f%%) args=%.2fms(%.1f%%) cookie=%.2fms(%.1f%%)",
            _count,
            _total_t*1000, _total_t*1000/_count,
            _cip_t*1000, _cip_t/_total_t*100,
            _wip_t*1000, _wip_t/_total_t*100,
            _dblk_t*1000, _dblk_t/_total_t*100,
            _bip_t*1000, _bip_t/_total_t*100,
            _wurl_t*1000, _wurl_t/_total_t*100,
            _ua_t*1000, _ua_t/_total_t*100,
            _url_t*1000, _url_t/_total_t*100,
            _args_t*1000, _args_t/_total_t*100,
            _cookie_t*1000, _cookie_t/_total_t*100
        ))
    end
end

local ok, err = pcall(waf_main_debug)
if not ok then ngx.log(ngx.ERR, "debug error: ", err) end
LUAEOF

sed -i 's|access_by_lua_file "lua/waf/access.lua"|access_by_lua_file "lua/waf/access_debug.lua"|' $NGINX_CONF

kill -TERM $(cat /opt/nginx/logs/nginx.pid) 2>/dev/null; sleep 2
cd /opt/nginx && ./nginx -p /opt/nginx/ -c conf/nginx.conf 2>&1; sleep 2

echo "===== 场景1: 不带 XFF 头 (10000请求, 100并发) =====" | tee -a $RESULT_FILE
ab -n 1000 -c 50 -k -H "User-Agent: Mozilla/5.0" http://127.0.0.1/ >/dev/null 2>&1
ab -n 10000 -c 100 -k -H "User-Agent: Mozilla/5.0" http://127.0.0.1/ 2>&1 | grep -E "Requests per second|Time per request.*mean" | tee -a $RESULT_FILE
echo "--- BENCH 日志 ---" | tee -a $RESULT_FILE
grep "BENCH" /opt/nginx/log/error.log 2>/dev/null | tail -3 | tee -a $RESULT_FILE

# 重置 shared dict 计数器
curl -s -o /dev/null http://127.0.0.1/?reset=1

echo "" | tee -a $RESULT_FILE
echo "===== 场景2: 带 XFF 头 (10000请求, 100并发) =====" | tee -a $RESULT_FILE
# 清除之前的日志
> /tmp/bench_before_xff.txt
grep "BENCH" /opt/nginx/log/error.log > /tmp/bench_before_xff.txt 2>/dev/null
ab -n 1000 -c 50 -k -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 1.2.3.4" http://127.0.0.1/ >/dev/null 2>&1
ab -n 10000 -c 100 -k -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 1.2.3.4" http://127.0.0.1/ 2>&1 | grep -E "Requests per second|Time per request.*mean" | tee -a $RESULT_FILE
echo "--- BENCH 日志 ---" | tee -a $RESULT_FILE
grep "BENCH" /opt/nginx/log/error.log 2>/dev/null | grep -v -f /tmp/bench_before_xff.txt | tail -3 | tee -a $RESULT_FILE

# 恢复
cp ${NGINX_CONF}.bak_d5 $NGINX_CONF
cp ${WAF_CONFIG}.bak_d5 $WAF_CONFIG
rm -f /opt/nginx/lua/waf/access_debug.lua ${NGINX_CONF}.bak_d5 ${WAF_CONFIG}.bak_d5
kill -TERM $(cat /opt/nginx/logs/nginx.pid) 2>/dev/null; sleep 2
./nginx -p /opt/nginx/ -c conf/nginx.conf 2>&1; sleep 2
echo "" | tee -a $RESULT_FILE
echo "===== 恢复完成 =====" | tee -a $RESULT_FILE
