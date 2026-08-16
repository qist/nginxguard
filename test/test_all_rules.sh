#!/bin/bash
# NginxGuard 规则全量测试
# 测试目标: 192.168.2.180 (NginxGuard on port 80)
# 参考: /opt/caddyguard 的测试点设计
# 规则引擎: NginxGuard (access.lua + lib.lua + config.lua)
# 规则版本: 2026-08-14 最新

TARGET="http://192.168.2.180"
PASS=0; FAIL=0; TOTAL=0; ERRORS=""
RESULTS="/tmp/waf_test_results.txt"
> $RESULTS

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

log()  { echo "[$(date '+%H:%M:%S')] $*" | tee -a $RESULTS; }
ok()   { echo -e "  ${GREEN}PASS${NC}  $1  (HTTP $2)" | tee -a $RESULTS; PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); }
bad()  { echo -e "  ${RED}FAIL${NC}  $1  (got $2, want $3)" | tee -a $RESULTS; FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); ERRORS="$ERRORS\n  $1: got $2, want $3"; }

test_rule() {
    local name="$1"; local expect="$2"; shift 2
    local actual=$(curl -s -m 10 -o /dev/null -w "%{http_code}" "$@" 2>/dev/null)
    if [ "$actual" = "$expect" ]; then ok "$name" "$actual"; else bad "$name" "$actual" "$expect"; fi
}

echo "========================================" | tee -a $RESULTS
echo "  NginxGuard 规则全量测试" | tee -a $RESULTS
echo "  目标: $TARGET (192.168.2.180:80)" | tee -a $RESULTS
echo "  时间: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a $RESULTS
echo "========================================" | tee -a $RESULTS
echo "" | tee -a $RESULTS

# 0. 基础连通性
echo -e "${CYAN}=== 0. 基础连通性 ===${NC}" | tee -a $RESULTS
code=$(curl -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "$TARGET/")
if [ "$code" = "200" ]; then log "NginxGuard 已启动 (HTTP 200)"; else log "FATAL: HTTP $code"; exit 1; fi
echo "" | tee -a $RESULTS

# 1. 正常请求
echo -e "${CYAN}=== 1. 正常请求（期望 200）===${NC}" | tee -a $RESULTS
test_rule "Normal GET" 200 -H "User-Agent: Mozilla/5.0" "$TARGET/"
test_rule "Normal args" 200 -H "User-Agent: Mozilla/5.0" "$TARGET/?id=123&name=hello"
test_rule "Normal POST" 200 -H "User-Agent: Mozilla/5.0" -d "test=hello_world_data_padding" "$TARGET/"
test_rule "Normal POST login" 200 -H "User-Agent: Mozilla/5.0" -d "username=admin&password=test123" "$TARGET/"
echo "" | tee -a $RESULTS

# 2. URL 路径攻击 (url.rule)
echo -e "${CYAN}=== 2. URL 路径攻击检测 (url.rule) ===${NC}" | tee -a $RESULTS
for path in \
    /etc/passwd /etc/shadow /.env /.htaccess /.htpasswd \
    /wp-admin/ /wp-login.php /phpinfo.php /xmlrpc.php /administrator/ \
    /actuator/env /actuator/health /actuator/beans /h2-console /druid/ \
    /swagger-ui /api-docs /v2/api-docs /.git/config /.svn/ \
    /proc/self/environ /var/log/test /boot.ini /cmd.exe /cgi-bin/test \
    /manager/html /jmx-console/ /struts2 /console /composer.json \
    /package.json /Dockerfile /.gitignore /docker-compose.yml \
    /.idea/workspace /.vscode/settings /id_rsa /.ssh/authorized_keys \
    /terraform.tfstate /firebase.json /gcp-key.json /sa.json \
    /.aws/credentials /shell.php /eval.php /config.json /test.sql \
    /.DS_Store /server-status /WEB-INF/web.xml /Pipfile \
    /requirements.txt /.npmrc /yarn.lock /swagger-resources \
    /server-info /scripts/ /rest/ /backup/test /upload.php \
    /connector.php /config.yml /database.sql /credentials \
    /id_dsa /authorized_keys /.gcloud/ /gc-service.json /push_config.json; do
    test_rule "Path $path" 403 -H "User-Agent: Mozilla/5.0" "${TARGET}${path}"
done
echo "" | tee -a $RESULTS
