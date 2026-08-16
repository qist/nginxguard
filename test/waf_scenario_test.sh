#!/bin/bash
# NginxGuard 场景测试: UA白名单+其他攻击拦截 / 域名独立规则 / Location开关
# 精简版, 只测关键点

TARGET="http://192.168.2.180"
SSH180="ssh 192.168.2.180"
NGINX_CMD="/opt/nginx/nginx -c /opt/nginx/conf/nginx.conf"
WAF_CONFIG="/opt/nginx/lua/waf/config.lua"
PASS=0; FAIL=0; TOTAL=0; ERRORS=""
RESULTS="/tmp/waf_scenario_test.txt"
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
set_config() { $SSH180 "sed -i 's/^config_$1 = .*/config_$1 = \"$2\"/' $WAF_CONFIG"; }
restart_nginx() { $SSH180 "$NGINX_CMD -s stop 2>/dev/null; sleep 1; $NGINX_CMD 2>&1"; sleep 2; }

echo "========================================" | tee -a $RESULTS
echo "  NginxGuard 场景测试" | tee -a $RESULTS
echo "  时间: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a $RESULTS
echo "========================================" | tee -a $RESULTS

# 预处理: 重启 + 关闭 CC
restart_nginx
set_config "cc_check" "off"
sleep 3
$SSH180 "$NGINX_CMD -s reload 2>&1"
sleep 2

# ============================================================
# 场景1: UA白名单放行, 但其他攻击仍拦截
# (whiteua.rule 只跳过 useragent.rule 黑名单, 不跳过 URL/POST/Cookie 等)
# ============================================================
echo -e "\n${CYAN}=== 场景1: UA白名单 + 其他攻击拦截 ===${NC}" | tee -a $RESULTS
echo -e "${YELLOW}  --- 白名单UA + 正常请求 (期望 200) ---${NC}" | tee -a $RESULTS
test_rule "Googlebot + 正常GET" 200 -A "Googlebot/2.1" "$TARGET/"
test_rule "Baiduspider + 正常GET" 200 -A "Baiduspider" "$TARGET/"
test_rule "Googlebot + 正常args" 200 -A "Googlebot/2.1" "$TARGET/?id=123"

echo -e "${YELLOW}  --- 白名单UA + URL路径攻击 (应拦截 403) ---${NC}" | tee -a $RESULTS
test_rule "Googlebot + /etc/passwd" 403 -A "Googlebot/2.1" "$TARGET/etc/passwd"
test_rule "Googlebot + /.env" 403 -A "Googlebot/2.1" "$TARGET/.env"
test_rule "Googlebot + /wp-admin/" 403 -A "Googlebot/2.1" "$TARGET/wp-admin/"
test_rule "Baiduspider + /actuator/env" 403 -A "Baiduspider" "$TARGET/actuator/env"

echo -e "${YELLOW}  --- 白名单UA + URL参数攻击 (应拦截 403) ---${NC}" | tee -a $RESULTS
test_rule "Googlebot + SQL注入" 403 -A "Googlebot/2.1" "$TARGET/?id=1+union+select+1"
test_rule "Googlebot + XSS" 403 -A "Googlebot/2.1" "$TARGET/?q=<script>alert(1)</script>"
test_rule "Baiduspider + 路径遍历" 403 -A "Baiduspider" "$TARGET/?file=../../../etc/passwd"
test_rule "Googlebot + 命令注入" 403 -A "Googlebot/2.1" "$TARGET/?q=system(ls)"

echo -e "${YELLOW}  --- 白名单UA + Cookie攻击 (应拦截 403) ---${NC}" | tee -a $RESULTS
test_rule "Googlebot + Cookie SQL" 403 -A "Googlebot/2.1" -b "id=1+union+select+1" "$TARGET/"
test_rule "Googlebot + Cookie XSS" 403 -A "Googlebot/2.1" -b "q=<script>alert(1)</script>" "$TARGET/"

echo -e "${YELLOW}  --- 白名单UA + POST攻击 (应拦截 403) ---${NC}" | tee -a $RESULTS
test_rule "Googlebot + POST SQL" 403 -A "Googlebot/2.1" -d "id=1+union+select+1" "$TARGET/"
test_rule "Googlebot + POST XSS" 403 -A "Googlebot/2.1" -d "q=<script>alert(1)</script>" "$TARGET/"

echo -e "${YELLOW}  --- 白名单UA + 文件上传攻击 (应拦截 403) ---${NC}" | tee -a $RESULTS
echo "x" | ssh 192.168.2.180 'cat > /tmp/test.sql'
code=$(ssh 192.168.2.180 "curl --globoff -s -m 5 -o /dev/null -w '%{http_code}' -A 'Googlebot/2.1' -F 'file=@/tmp/test.sql' http://127.0.0.1:80/")
if [ "$code" = "403" ]; then ok "Googlebot + Upload .sql" "$code"; else bad "Googlebot + Upload .sql" "$code" "403"; fi

# ============================================================
# 场景2: 域名独立配置规则
# domain.json 中 www.example.com: url_check=off, rule_dir=domains/www.example.com
# api.example.com: waf_enable=off
# *.test.com: post_check=off, cookie_check=off
# ============================================================
echo -e "\n${CYAN}=== 场景2: 域名独立配置规则 ===${NC}" | tee -a $RESULTS

echo -e "${YELLOW}  --- www.example.com (url_check=off, 独立rule_dir) ---${NC}" | tee -a $RESULTS
# url_check=off: URL路径攻击应放行 (NginxGuard不拦截, nginx找不到文件返回404)
test_rule "www.example.com /etc/passwd (url_check=off, 404=放行)" 404 -H "Host: www.example.com" -A "Mozilla/5.0" "$TARGET/etc/passwd"
test_rule "www.example.com /.env (url_check=off, 404=放行)" 404 -H "Host: www.example.com" -A "Mozilla/5.0" "$TARGET/.env"
test_rule "www.example.com /wp-admin/ (url_check=off, 404=放行)" 404 -H "Host: www.example.com" -A "Mozilla/5.0" "$TARGET/wp-admin/"
# 但 URL参数攻击仍应拦截 (url_args_check 仍 on, 用域名独立 args.rule)
test_rule "www.example.com SQL注入 (args仍on)" 403 -H "Host: www.example.com" -A "Mozilla/5.0" "$TARGET/?id=1+union+select+1"
test_rule "www.example.com XSS (args仍on)" 403 -H "Host: www.example.com" -A "Mozilla/5.0" "$TARGET/?q=<script>alert(1)</script>"
# 域名独立 useragent.rule (可能不同规则)
test_rule "www.example.com sqlmap UA" 403 -H "Host: www.example.com" -A "sqlmap/1.0" "$TARGET/"
# POST 仍检测
test_rule "www.example.com POST SQL (post仍on)" 403 -H "Host: www.example.com" -A "Mozilla/5.0" -d "id=1+union+select+1" "$TARGET/"
# 域名独立 whiteurl (NginxGuard放行, nginx找不到文件返回404)
test_rule "www.example.com 白名单URL /123/ (404=放行)" 404 -H "Host: www.example.com" -A "Mozilla/5.0" "$TARGET/123/"
# 域名独立 whiteip
test_rule "www.example.com 白名单IP 8.8.8.8" 200 -H "Host: www.example.com" -A "Mozilla/5.0" -H "X-Forwarded-For: 8.8.8.8" "$TARGET/?id=union+select"

echo -e "${YELLOW}  --- api.example.com (waf_enable=off, 全部放行) ---${NC}" | tee -a $RESULTS
test_rule "api.example.com SQL注入 (waf off)" 200 -H "Host: api.example.com" -A "Mozilla/5.0" "$TARGET/?id=1+union+select+1"
test_rule "api.example.com XSS (waf off)" 200 -H "Host: api.example.com" -A "Mozilla/5.0" "$TARGET/?q=<script>alert(1)</script>"
test_rule "api.example.com /etc/passwd (waf off, 404=放行)" 404 -H "Host: api.example.com" -A "Mozilla/5.0" "$TARGET/etc/passwd"
test_rule "api.example.com sqlmap UA (waf off)" 200 -H "Host: api.example.com" -A "sqlmap/1.0" "$TARGET/"
test_rule "api.example.com POST SQL (waf off, 405=放行)" 405 -H "Host: api.example.com" -A "Mozilla/5.0" -d "id=1+union+select+1" "$TARGET/"

echo -e "${YELLOW}  --- test.test.com (*.test.com: post=off, cookie=off) ---${NC}" | tee -a $RESULTS
# post_check=off: POST攻击应放行 (NginxGuard不拦截, nginx静态root返回405)
test_rule "test.test.com POST SQL (post=off, 405=放行)" 405 -H "Host: test.test.com" -A "Mozilla/5.0" -d "id=1+union+select+1" "$TARGET/"
test_rule "test.test.com POST XSS (post=off, 405=放行)" 405 -H "Host: test.test.com" -A "Mozilla/5.0" -d "q=<script>alert(1)</script>" "$TARGET/"
# cookie_check=off: Cookie攻击应放行
test_rule "test.test.com Cookie SQL (cookie=off)" 200 -H "Host: test.test.com" -A "Mozilla/5.0" -b "id=1+union+select+1" "$TARGET/"
# 但URL攻击仍应拦截
test_rule "test.test.com SQL注入 (url仍on)" 403 -H "Host: test.test.com" -A "Mozilla/5.0" "$TARGET/?id=1+union+select+1"
test_rule "test.test.com /etc/passwd (url仍on)" 403 -H "Host: test.test.com" -A "Mozilla/5.0" "$TARGET/etc/passwd"
test_rule "test.test.com sqlmap UA (ua仍on)" 403 -H "Host: test.test.com" -A "sqlmap/1.0" "$TARGET/"

echo -e "${YELLOW}  --- 未知域名 (走全局配置) ---${NC}" | tee -a $RESULTS
test_rule "unknown.com SQL注入 (全局)" 403 -H "Host: unknown.com" -A "Mozilla/5.0" "$TARGET/?id=1+union+select+1"
test_rule "unknown.com /etc/passwd (全局)" 403 -H "Host: unknown.com" -A "Mozilla/5.0" "$TARGET/etc/passwd"

# ============================================================
# 场景3: Location 级 NginxGuard 开关
# /nowaf/ location 中 set $waf_enable off
# ============================================================
echo -e "\n${CYAN}=== 场景3: Location 级 NginxGuard 开关 ===${NC}" | tee -a $RESULTS

echo -e "${YELLOW}  --- /nowaf/ 下全部放行 ---${NC}" | tee -a $RESULTS
test_rule "/nowaf/ 正常GET" 200 -A "Mozilla/5.0" "$TARGET/nowaf/"
test_rule "/nowaf/ SQL注入" 200 -A "Mozilla/5.0" "$TARGET/nowaf/?id=1+union+select+1"
test_rule "/nowaf/ XSS" 200 -A "Mozilla/5.0" "$TARGET/nowaf/?q=<script>alert(1)</script>"
test_rule "/nowaf/ 路径遍历" 200 -A "Mozilla/5.0" "$TARGET/nowaf/?file=../../../etc/passwd"
test_rule "/nowaf/ 命令注入" 200 -A "Mozilla/5.0" "$TARGET/nowaf/?q=system(ls)"
test_rule "/nowaf/ sqlmap UA" 200 -A "sqlmap/1.0" "$TARGET/nowaf/"
test_rule "/nowaf/ Cookie攻击" 200 -A "Mozilla/5.0" -b "id=1+union+select+1" "$TARGET/nowaf/"
test_rule "/nowaf/ /etc/passwd路径 (404=放行)" 404 -A "Mozilla/5.0" "$TARGET/nowaf/etc/passwd"

echo -e "${YELLOW}  --- / (非/nowaf/) 下仍拦截 ---${NC}" | tee -a $RESULTS
test_rule "/ SQL注入 (应拦截)" 403 -A "Mozilla/5.0" "$TARGET/?id=1+union+select+1"
test_rule "/ /etc/passwd (应拦截)" 403 -A "Mozilla/5.0" "$TARGET/etc/passwd"
test_rule "/ sqlmap UA (应拦截)" 403 -A "sqlmap/1.0" "$TARGET/"

# ============================================================
# 场景4: Location开关 + 域名配置叠加
# www.example.com 的 /nowaf/ 也应该放行
# ============================================================
echo -e "\n${CYAN}=== 场景4: Location开关 + 域名叠加 ===${NC}" | tee -a $RESULTS
test_rule "www.example.com /nowaf/ SQL注入" 200 -H "Host: www.example.com" -A "Mozilla/5.0" "$TARGET/nowaf/?id=1+union+select+1"
test_rule "api.example.com /nowaf/ 正常" 200 -H "Host: api.example.com" -A "Mozilla/5.0" "$TARGET/nowaf/"

# ============================================================
# 场景5: Location开关 + 白名单UA叠加
# /nowaf/ 下 Googlebot 也应放行 (虽然本来就放行)
# ============================================================
echo -e "\n${CYAN}=== 场景5: Location开关 + 白名单UA ===${NC}" | tee -a $RESULTS
test_rule "/nowaf/ Googlebot + SQL注入" 200 -A "Googlebot/2.1" "$TARGET/nowaf/?id=1+union+select+1"
test_rule "/nowaf/ Googlebot + /etc/passwd (404=放行)" 404 -A "Googlebot/2.1" "$TARGET/nowaf/etc/passwd"

# 后处理: 恢复 CC
set_config "cc_check" "on"
restart_nginx
log "CC 已恢复, nginx 已重启"

# 汇总
echo "" | tee -a $RESULTS
echo "========================================" | tee -a $RESULTS
echo "  场景测试汇总" | tee -a $RESULTS
echo "  PASS: $PASS  FAIL: $FAIL  TOTAL: $TOTAL" | tee -a $RESULTS
echo "========================================" | tee -a $RESULTS
if [ $FAIL -gt 0 ]; then echo -e "失败项:$ERRORS" | tee -a $RESULTS; fi
echo ""
