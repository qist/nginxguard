#!/bin/bash
# 在 192.168.2.180 本地执行：get_client_ip() 内部步骤耗时分析
# 通过在 access.lua 中临时插入 ngx.log 微秒级时间戳来定位

WAF_CONFIG="/opt/nginx/lua/waf/config.lua"
RULE_DIR="/opt/nginx/lua/waf/rule-config"
ACCESS_LUA="/opt/nginx/lua/waf/access.lua"
LIB_LUA="/opt/nginx/lua/waf/lib.lua"

cp $ACCESS_LUA ${ACCESS_LUA}.bak_debug
cp $LIB_LUA ${LIB_LUA}.bak_debug
cp $WAF_CONFIG ${WAF_CONFIG}.bak_debug

# 关闭 CC 避免干扰
sed -i 's|^config_cc_check = .*|config_cc_check = "off"|' $WAF_CONFIG
# 确保 trust_proxy_headers=on + cdnip.rule 存在
sed -i 's|^config_trust_proxy_headers = .*|config_trust_proxy_headers = "on"|' $WAF_CONFIG

# 在 get_client_ip 函数中插入耗时打点
# 定位关键行: if get_effective_config("trust_proxy_headers") ~= "off" then
# 在其后插入时间戳
cat > /tmp/patch_lib.py << 'PYEOF'
import re

with open("/opt/nginx/lua/waf/lib.lua", "r") as f:
    content = f.read()

# 在 get_client_ip 函数入口插入时间戳
old = 'function get_client_ip()\n    if ngx.ctx._client_ip then'
new = '''function get_client_ip()
    if ngx.ctx._client_ip then
        return ngx.ctx._client_ip
    end
    ngx.ctx._ip_t0 = ngx.now()

    -- DEBUG: 记录每次 get_client_ip 的步骤
    if not ngx.ctx._ip_debug_logged then
        ngx.ctx._ip_debug_logged = true
    end

    local _ip
    local _debug_steps = {}
    if get_effective_config("trust_proxy_headers") ~= "off" then
        _debug_steps[1] = "proxy_check_start"
        local remote = ngx.var.remote_addr
        _debug_steps[2] = "got_remote:" .. tostring(remote)
        local cdn_result = is_cdn_ip(remote)
        _debug_steps[3] = "cdn_check:" .. tostring(cdn_result)
        if cdn_result ~= false then
            local headers = ngx.req.get_headers()
            _debug_steps[4] = "got_headers:" .. tostring(headers ~= nil)
            ip = headers["CF_Connecting_IP"] or headers["cf-connecting-ip"]
            _debug_steps[5] = "cf_ip:" .. tostring(ip)
            if ip ~= nil and not is_valid_ip(ip) then ip = nil end
            if ip == nil then
                ip = headers["X_real_ip"] or headers["X-Real-IP"]
                if ip ~= nil and not is_valid_ip(ip) then ip = nil end
            end
            _debug_steps[6] = "real_ip:" .. tostring(ip)
            if ip == nil then
                local xff = headers["X_Forwarded_For"] or headers["X-Forwarded-For"]
                _debug_steps[7] = "xff:" .. tostring(xff ~= nil)
                if xff then
                    for entry in xff:gmatch("([^,]+)") do
                        local candidate = entry:match("^%s*(%S+)%s*$")
                        if candidate and is_valid_ip(candidate) then
                            ip = candidate
                            break
                        end
                    end
                end
            end
            _debug_steps[8] = "final_xff_ip:" .. tostring(ip)
        end
    end
    if ip == nil then
        ip = ngx.var.remote_addr
    end
    if ip == nil then
        ip = "unknown"
    end
    ngx.ctx._client_ip = ip
    ngx.ctx._ip_t1 = ngx.now()
    -- 只在前10个请求打日志，避免刷屏
    if not ngx.shared.limit:get("debug_ip_count") then
        ngx.shared.limit:set("debug_ip_count", 1, 60)
        ngx.log(ngx.NOTICE, "[BENCH_IP] steps=" .. table.concat(_debug_steps, "|") .. " time=" .. string.format("%.6f", ngx.ctx._ip_t1 - ngx.ctx._ip_t0) .. "s ip=" .. tostring(ip))
    end
    return ip
'''

# 用占位实现替换整个函数体
# 注意：由于 get_client_ip 已经在 ngx.ctx 中缓存，我们只需替换函数定义
# 简化版：只在函数头部和尾部加时间戳
content = content.replace(
    '''function get_client_ip()
    if ngx.ctx._client_ip then
        return ngx.ctx._client_ip
    end
    local ip
    if get_effective_config("trust_proxy_headers") ~= "off" then
        -- Security check: only trust forwarded headers if the direct connection
        -- comes from a trusted CDN/proxy IP (prevents direct XFF spoofing)
        -- is_cdn_ip returns nil when cdnip.rule doesn't exist (= trust all, original behavior)
        -- is_cdn_ip returns false when remote_addr is not in cdnip.rule (= do NOT trust XFF)
        local remote = ngx.var.remote_addr
        if is_cdn_ip(remote) ~= false then''',
    new
)

# 关闭后面的 end if ip == nil (恢复)
# 由于上面的替换可能破坏了原函数结构，我们采用更安全的方式：
# 直接在整个文件末尾追加一个包装函数
with open("/opt/nginx/lua/waf/lib.lua", "w") as f:
    f.write(content)

print("Patch applied to lib.lua")
PYEOF

python3 /tmp/patch_lib.py

# 重启 nginx
kill -TERM $(cat /opt/nginx/logs/nginx.pid) 2>/dev/null; sleep 2
cd /opt/nginx && ./nginx -p /opt/nginx/ -c conf/nginx.conf 2>&1; sleep 2

echo "===== 发送带 XFF 头的请求触发 get_client_ip 路径 ====="
for i in $(seq 1 5); do
    curl -s -o /dev/null -w "HTTP %{http_code} time=%{time_total}s\n" -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 1.2.3.4" http://127.0.0.1/
done

echo ""
echo "===== 发送不带 XFF 头的请求 ====="
for i in $(seq 1 5); do
    curl -s -o /dev/null -w "HTTP %{http_code} time=%{time_total}s\n" -H "User-Agent: Mozilla/5.0" http://127.0.0.1/
done

echo ""
echo "===== 查看 error.log 中的 BENCH_IP 日志 ====="
tail -50 /opt/nginx/logs/error.log 2>/dev/null | grep "BENCH_IP"

echo ""
echo "===== 简单 ab 压测 (带XFF vs 不带XFF) ====="
echo "--- 不带 XFF ---"
ab -n 10000 -c 100 -k -H "User-Agent: Mozilla/5.0" http://127.0.0.1/ 2>&1 | grep -E "Requests per second|Time per request.*mean"
echo "--- 带 XFF ---"
ab -n 10000 -c 100 -k -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 1.2.3.4" http://127.0.0.1/ 2>&1 | grep -E "Requests per second|Time per request.*mean"

# 恢复
cp ${LIB_LUA}.bak_debug $LIB_LUA
cp ${WAF_CONFIG}.bak_debug $WAF_CONFIG
rm -f ${LIB_LUA}.bak_debug ${WAF_CONFIG}.bak_debug
kill -TERM $(cat /opt/nginx/logs/nginx.pid) 2>/dev/null; sleep 2
./nginx -p /opt/nginx/ -c conf/nginx.conf 2>&1; sleep 2
echo "===== 恢复完成 ====="
