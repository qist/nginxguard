#!/bin/bash
# NginxGuard 规则全量测试 v2
# 测试目标: 192.168.2.180 (NginxGuard on port 80)
# 关键: 测试期间临时关闭 CC, CC 测试时临时开启, 测试后重启 nginx 清除封禁

TARGET="http://192.168.2.180"
SSH180="ssh 192.168.2.180"
NGINX_CMD="cd /opt/nginx && ./nginx -p /opt/nginx/ -c conf/nginx.conf"
WAF_CONFIG="/opt/nginx/lua/waf/config.lua"
WAF_LOG_DIR="/opt/nginx/log"
PASS=0; FAIL=0; TOTAL=0; ERRORS=""
RESULTS="/tmp/waf_test_results.txt"
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

echo "========================================" | tee -a $RESULTS
echo "  NginxGuard 规则全量测试 v2" | tee -a $RESULTS
echo "  目标: $TARGET" | tee -a $RESULTS
echo "  时间: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a $RESULTS
echo "========================================" | tee -a $RESULTS

# 预处理: 重启 nginx 清除 CC 封禁 + 临时关闭 CC
echo -e "${CYAN}=== 预处理: 重启 nginx + 临时关闭 CC ===${NC}" | tee -a $RESULTS
restart_nginx
set_config "cc_check" "off"
sleep 3
$SSH180 "$NGINX_CMD -s reload 2>&1"
sleep 2

# 0. 基础连通性
echo -e "${CYAN}=== 0. 基础连通性 ===${NC}" | tee -a $RESULTS
code=$(curl --globoff -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "$TARGET/")
if [ "$code" = "200" ]; then log "NginxGuard 已启动 (HTTP 200), CC 已临时关闭"; else log "FATAL: HTTP $code"; exit 1; fi
echo "" | tee -a $RESULTS

# 1. 正常请求
echo -e "${CYAN}=== 1. 正常请求 ===${NC}" | tee -a $RESULTS
test_rule "Normal GET" 200 -H "User-Agent: Mozilla/5.0" "$TARGET/"
test_rule "Normal args" 200 -H "User-Agent: Mozilla/5.0" "$TARGET/?id=123&name=hello"
test_rule "Normal POST (405)" 405 -H "User-Agent: Mozilla/5.0" -d "test=hello_world_data_padding" "$TARGET/"
test_rule "Normal POST login (405)" 405 -H "User-Agent: Mozilla/5.0" -d "username=admin&password=test123" "$TARGET/"
echo "" | tee -a $RESULTS

# 2. URL 路径攻击 (url.rule)
echo -e "${CYAN}=== 2. URL 路径攻击检测 (url.rule) ===${NC}" | tee -a $RESULTS
for path in /etc/passwd /etc/shadow /.env /.htaccess /.htpasswd /wp-admin/ /wp-login.php /phpinfo.php /xmlrpc.php /administrator/ /actuator/env /actuator/health /actuator/beans /h2-console /druid/ /swagger-ui /api-docs /v2/api-docs /.git/config /.svn/ /proc/self/environ /var/log/test /boot.ini /cmd.exe /cgi-bin/test /manager/html /jmx-console/ /struts2 /console /composer.json /package.json /Dockerfile /.gitignore /docker-compose.yml /.idea/workspace /.vscode/settings /id_rsa /.ssh/authorized_keys /terraform.tfstate /firebase.json /gcp-key.json /sa.json /.aws/credentials /shell.php /eval.php /config.json /test.sql /.DS_Store /server-status /WEB-INF/web.xml /Pipfile /requirements.txt /.npmrc /yarn.lock /swagger-resources /server-info /scripts/ /upload.php /connector.php /config.yml /database.sql /credentials /id_dsa /authorized_keys /.gcloud/ /gc-service.json /push_config.json; do
    test_rule "Path $path" 403 -H "User-Agent: Mozilla/5.0" "${TARGET}${path}"
done
echo "" | tee -a $RESULTS

# 3. URL 参数攻击 (args.rule)
echo -e "${CYAN}=== 3. URL 参数攻击检测 (args.rule) ===${NC}" | tee -a $RESULTS
echo -e "${YELLOW}  --- SQL 注入 ---${NC}" | tee -a $RESULTS
test_rule "SQL union select" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?id=1+union+select+1"
test_rule "SQL union full" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?id=1+union+select+1,2,3"
test_rule "SQL sleep()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?id=sleep(5)"
test_rule "SQL benchmark()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?id=benchmark(1000000,md5(1))"
test_rule "SQL base64_decode()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=base64_decode(aGVsbG8=)"
test_rule "SQL info_schema" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=select+from+information_schema.tables"
test_rule "SQL having" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=having+1=1"
test_rule "SQL and 1=1" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?id=1+and+1=1"
test_rule "SQL or 1=1" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?id=1+or+1=1"
test_rule "SQL order by" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?id=1+order+by+1"
test_rule "SQL LOAD_FILE()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=LOAD_FILE('/etc/passwd')"
test_rule "SQL CONCAT()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=CONCAT(user(),0x3a)"
test_rule "SQL CHAR()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=CHAR(74,65,73,74)"
test_rule "SQL HEX()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=HEX('test')"
test_rule "SQL UNHEX()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=UNHEX('74657374')"
test_rule "SQL PG_SLEEP()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=PG_SLEEP(5)"
test_rule "SQL WAITFOR DELAY" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=WAITFOR+DELAY+'0:0:5'"
test_rule "SQL DBMS_PIPE" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=DBMS_PIPE.RECEIVE_MESSAGE('a',5)"
test_rule "SQL extractvalue()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=extractvalue(1,concat(0x7e,user()))"
test_rule "SQL updatexml()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=updatexml(1,concat(0x7e,user()),1)"
test_rule "SQL group by" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=group+by+(user)"
test_rule "SQL INTO OUTFILE" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=SELECT+*+INTO+OUTFILE+'/tmp/t'"
test_rule "SQL INTO DUMPFILE" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=INTO+DUMPFILE+'/tmp/t'"
test_rule "SQL LOAD DATA" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=LOAD+DATA+INFILE+'/etc/passwd'"

echo -e "${YELLOW}  --- XSS 攻击 ---${NC}" | tee -a $RESULTS
test_rule "XSS <script>" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=<script>alert(1)</script>"
test_rule "XSS <iframe>" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=<iframe>test</iframe>"
test_rule "XSS <img onerror>" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=<img+src=x+onerror=alert(1)>"
test_rule "XSS <svg onload>" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=<svg+onload=alert(1)>"
test_rule "XSS <body onload>" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=<body+onload=alert(1)>"
test_rule "XSS <div onmouseover>" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=<div+onmouseover=alert(1)>"
test_rule "XSS <meta>" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=<meta+http-equiv=refresh>"
test_rule "XSS <object>" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=<object+data=javascript:alert(1)>"
test_rule "XSS <input>" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=<input+onfocus=alert(1)>"
test_rule "XSS <layer>" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=<layer+src=javascript:alert(1)>"
test_rule "XSS <base>" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=<base+href=javascript:alert(1)>"
test_rule "XSS <style>" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=<style>test</style>"
test_rule "XSS onmouseover=" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=onmouseover=alert(1)"
test_rule "XSS onerror=" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=onerror=alert(1)"
test_rule "XSS onload=" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=onload=alert(1)"
test_rule "XSS onclick=" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=onclick=alert(1)"
test_rule "XSS javascript:" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=javascript:alert(1)"
test_rule "XSS vbscript:" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=vbscript:msgbox(1)"
test_rule "XSS document.cookie" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=document.cookie"
test_rule "XSS document.write" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=document.write(1)"
test_rule "XSS String.fromCharCode" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=String.fromCharCode(74)"
test_rule "XSS window.location" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=window.location=test"
test_rule "XSS window.open" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=window.open('http://evil.com')"
test_rule "XSS alert()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=alert(1)"
test_rule "XSS confirm()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=confirm(1)"
test_rule "XSS prompt()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=prompt(1)"
test_rule "XSS %3Cscript" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%3Cscript%3Ealert(1)%3C/script%3E"
test_rule "XSS %3Ciframe" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%3Ciframe%3Etest%3C/iframe%3E"
test_rule "XSS %3Csvg" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%3Csvg%3Etest%3C/svg%3E"
test_rule "XSS %3Cimg" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%3Cimg+src=x+onerror=alert(1)%3E"
test_rule "XSS %22%3E%3Cscript" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%22%3E%3Cscript%3Ealert(1)%3C/script%3E"
test_rule "XSS %27%3E%3Cscript" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%27%3E%3Cscript%3Ealert(1)%3C/script%3E"

echo -e "${YELLOW}  --- 路径遍历/命令注入 ---${NC}" | tee -a $RESULTS
test_rule "Path traversal ../" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?file=../../../etc/passwd"
test_rule "Path traversal deep" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?file=../../../../etc/shadow"
test_rule "Cmd system()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=system(ls)"
test_rule "Cmd exec()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=exec('ls')"
test_rule "Cmd passthru()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=passthru('id')"
test_rule "Cmd shell_exec()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=shell_exec('whoami')"
test_rule "Cmd popen()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=popen('ls','r')"
test_rule "Cmd proc_open()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=proc_open('ls',[],pipes)"
test_rule "Cmd pcntl_exec()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=pcntl_exec('/bin/ls')"
test_rule "Cmd assert()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=assert(eval(cmd))"
test_rule "Cmd preg_replace /e" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=preg_replace('/.*/e','eval(0)','x')"
test_rule "Cmd create_function()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=create_function('',eval(0))"
test_rule "Cmd call_user_func()" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=call_user_func('system','ls')"
test_rule "Cmd expect://" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=expect://id"
test_rule "Cmd cmd=;ls" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?cmd=;ls;cat+/etc/passwd;whoami"
test_rule "Cmd perl" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=perl+test.pl"
test_rule "Cmd python" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=python+-c+import+os"
test_rule "Cmd gopher://" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=gopher://evil.com/x"
test_rule "Cmd file://" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=file:///etc/passwd"
test_rule "Cmd data://" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=data://text/plain,base64,aGVsbG8="

echo -e "${YELLOW}  --- NoSQL 注入 ---${NC}" | tee -a $RESULTS
test_rule 'NoSQL $eq(' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=\$eq(1)"
test_rule 'NoSQL $ne(' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=\$ne(null)"
test_rule 'NoSQL $gt(' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=\$gt(1)"
test_rule 'NoSQL $lt(' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=\$lt(10)"
test_rule 'NoSQL $gte(' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=\$gte(1)"
test_rule 'NoSQL $lte(' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=\$lte(10)"
test_rule 'NoSQL $where(' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=\$where(1==1)"
test_rule 'NoSQL $regex(' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=\$regex(/.*/)"
test_rule 'NoSQL $in(' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=\$in%281%29"
test_rule 'NoSQL $nin(' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=\$nin%281%29"
test_rule 'NoSQL $or(' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=\$or%28%29"
test_rule 'NoSQL $and(' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=\$and%28%29"
test_rule 'NoSQL $not(' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=\$not%28%29"
test_rule 'NoSQL $exists(' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=\$exists(1)"
test_rule 'NoSQL system.exec(' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=system.exec(\"ls\")"

echo -e "${YELLOW}  --- SSTI 模板注入 ---${NC}" | tee -a $RESULTS
test_rule "SSTI __class__" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%7B%7B__class__%7D%7D"
test_rule "SSTI __subclasses__" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%7B%7B__subclasses__%7D%7D"
test_rule "SSTI __init__" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%7B%7B__init__%7D%7D"
test_rule "SSTI __globals__" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%7B%7B__globals__%7D%7D"
test_rule "SSTI __builtins__" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%7B%7B__builtins__%7D%7D"
test_rule "SSTI __import__" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%7B%7B__import__%7D%7D"
test_rule "SSTI config" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%7B%7Bconfig%7D%7D"
test_rule "SSTI lipsum" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%7B%7Blipsum%7D%7D"
test_rule "SSTI cycler" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%7B%7Bcycler%7D%7D"
test_rule "SSTI namespace" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%7B%7Bnamespace%7D%7D"
test_rule "SSTI request.apply" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%7B%7Brequest.apply%7D%7D"
test_rule "SSTI joiner" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=%7B%7Bjoiner%7D%7D"

echo -e "${YELLOW}  --- PHP 代码注入 ---${NC}" | tee -a $RESULTS
test_rule 'PHP $_GET' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=\$_GET%5Bcmd%5D"
test_rule 'PHP $_POST' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=\$_POST%5Bdata%5D"
test_rule 'PHP $_COOKIE' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=\$_COOKIE%5Bsession%5D"
test_rule 'PHP $_SESSION' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=\$_SESSION%5Bid%5D"
test_rule 'PHP $_FILES' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=\$_FILES%5Bfile%5D"
test_rule 'PHP $_SERVER' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=\$_SERVER%5BDOCUMENT_ROOT%5D"
test_rule 'PHP eval()' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=eval(base64_decode(aGVsbG8=))"
test_rule 'PHP include()' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=include(\$_GET%5Bfile%5D)"
test_rule 'PHP require()' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=require(\$_GET%5Bfile%5D)"
test_rule 'PHP file_get_contents()' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=file_get_contents('/etc/passwd')"
test_rule 'PHP phpinfo()' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=phpinfo()"
test_rule 'PHP define()' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=define('test','value')"
test_rule 'PHP child_process' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=require('child_process')"
test_rule 'PHP spawn()' 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=spawn('ls')"

echo -e "${YELLOW}  --- 其他参数攻击 ---${NC}" | tee -a $RESULTS
test_rule "proc/self/environ" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=proc/self/environ"
test_rule "etc/passwd" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=etc/passwd"
test_rule "java.lang" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=java.lang.Runtime"
test_rule "mosconfig" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?q=mosconfig%5Boption%5D=1"
test_rule "and 1=2" 403 -H "User-Agent: Mozilla/5.0" "$TARGET/?id=1+and+1=2"
echo "" | tee -a $RESULTS

# 4. User-Agent 攻击检测 (useragent.rule)
echo -e "${CYAN}=== 4. User-Agent 攻击检测 (useragent.rule) ===${NC}" | tee -a $RESULTS
for ua_val in "sqlmap/1.0" "Nikto/2.1.6" "Nmap Scripting Engine" "DirBuster-1.0" "masscan/1.0" "dirb/1.0" "GoBuster/1.0" "ffuf/1.0" "Wfuzz/1.0" "Nuclei/1.0" "httpx/1.0" "feroxbuster/1.0" "Acunetix" "Nessus" "OpenVAS" "Burp Suite Professional" "AppScan" "Metasploit" "Qualys" "Python-urllib/3.9" "python-requests/2.28.0" "Go-http-client/1.1" "Scrapy/2.5"; do
    test_rule "UA $ua_val" 403 -A "$ua_val" "$TARGET/"
done
echo "" | tee -a $RESULTS

# 5. 白名单 UA 放行 (whiteua.rule)
echo -e "${CYAN}=== 5. 白名单 UA 放行测试 (whiteua.rule) ===${NC}" | tee -a $RESULTS
test_rule "UA Googlebot (whitelisted)" 200 -A "Googlebot/2.1" "$TARGET/"
test_rule "UA Baiduspider (whitelisted)" 200 -A "Baiduspider+(+http://www.baidu.com)" "$TARGET/"
test_rule "UA bingbot (whitelisted)" 200 -A "bingbot/2.0" "$TARGET/"
test_rule "UA YandexBot (whitelisted)" 200 -A "YandexBot/3.0" "$TARGET/"
test_rule "UA Applebot (whitelisted)" 200 -A "Applebot" "$TARGET/"
echo "" | tee -a $RESULTS

# 6. Cookie 攻击检测 (cookie.rule)
echo -e "${CYAN}=== 6. Cookie 攻击检测 (cookie.rule) ===${NC}" | tee -a $RESULTS
test_rule "Cookie SQL union" 403 -H "User-Agent: Mozilla/5.0" -b "id=1+union+select+1" "$TARGET/"
test_rule "Cookie SQL sleep" 403 -H "User-Agent: Mozilla/5.0" -b "id=sleep(5)" "$TARGET/"
test_rule "Cookie XSS script" 403 -H "User-Agent: Mozilla/5.0" -b "q=<script>alert(1)</script>" "$TARGET/"
test_rule "Cookie path traversal" 403 -H "User-Agent: Mozilla/5.0" -b "file=../../../etc/passwd" "$TARGET/"
test_rule "Cookie base64_decode" 403 -H "User-Agent: Mozilla/5.0" -b "q=base64_decode(aGVsbG8=)" "$TARGET/"
test_rule "Cookie system()" 403 -H "User-Agent: Mozilla/5.0" -b "q=system(ls)" "$TARGET/"
test_rule "Cookie eval()" 403 -H "User-Agent: Mozilla/5.0" -b "q=eval(base64_decode(aGVsbG8=))" "$TARGET/"
test_rule "Cookie SSTI" 403 -H "User-Agent: Mozilla/5.0" -b "q=%7B%7B__class__%7D%7D" "$TARGET/"
test_rule 'Cookie $_GET' 403 -H "User-Agent: Mozilla/5.0" -b 'q=$_GET[cmd]' "$TARGET/"
test_rule "Cookie document.cookie" 403 -H "User-Agent: Mozilla/5.0" -b "q=document.cookie" "$TARGET/"
echo "" | tee -a $RESULTS

# 7. POST 攻击检测 (post.rule)
echo -e "${CYAN}=== 7. POST 攻击检测 (post.rule) ===${NC}" | tee -a $RESULTS
test_rule "POST SQL union" 403 -H "User-Agent: Mozilla/5.0" -d "id=1+union+select+1" "$TARGET/"
test_rule "POST SQL sleep" 403 -H "User-Agent: Mozilla/5.0" -d "id=sleep(5)" "$TARGET/"
test_rule "POST SQL benchmark" 403 -H "User-Agent: Mozilla/5.0" -d "id=benchmark(1000000,md5(1))" "$TARGET/"
test_rule "POST SQL base64_decode" 403 -H "User-Agent: Mozilla/5.0" -d "x=base64_decode(aGVsbG8=)" "$TARGET/"
test_rule "POST SQL info_schema" 403 -H "User-Agent: Mozilla/5.0" -d "q=select+from+information_schema.tables" "$TARGET/"
test_rule "POST SQL having" 403 -H "User-Agent: Mozilla/5.0" -d "q=having+1=1" "$TARGET/"
test_rule "POST SQL and 1=1" 403 -H "User-Agent: Mozilla/5.0" -d "id=1+and+1=1" "$TARGET/"
test_rule "POST SQL or 1=1" 403 -H "User-Agent: Mozilla/5.0" -d "id=1+or+1=1" "$TARGET/"
test_rule "POST SQL CONCAT()" 403 -H "User-Agent: Mozilla/5.0" -d 'x=CONCAT(user(),0x3a)' "$TARGET/"
test_rule "POST SQL CHAR()" 403 -H "User-Agent: Mozilla/5.0" -d "x=CHAR(74,65,73,74)" "$TARGET/"
test_rule "POST SQL PG_SLEEP()" 403 -H "User-Agent: Mozilla/5.0" -d "q=PG_SLEEP(5)" "$TARGET/"
test_rule "POST SQL extractvalue" 403 -H "User-Agent: Mozilla/5.0" -d "q=extractvalue(1,concat(0x7e,user()))" "$TARGET/"
test_rule "POST SQL updatexml" 403 -H "User-Agent: Mozilla/5.0" -d "q=updatexml(1,concat(0x7e,user()),1)" "$TARGET/"
test_rule "POST XSS script" 403 -H "User-Agent: Mozilla/5.0" -d "q=<script>alert(1)</script>" "$TARGET/"
test_rule "POST XSS iframe" 403 -H "User-Agent: Mozilla/5.0" -d "q=<iframe>test</iframe>" "$TARGET/"
test_rule "POST XSS img onerror" 403 -H "User-Agent: Mozilla/5.0" -d 'q=<img+src=x+onerror=alert(1)>' "$TARGET/"
test_rule "POST path traversal" 403 -H "User-Agent: Mozilla/5.0" -d "file=../../../etc/passwd" "$TARGET/"
test_rule "POST system()" 403 -H "User-Agent: Mozilla/5.0" -d "x=system(ls)" "$TARGET/"
test_rule "POST exec()" 403 -H "User-Agent: Mozilla/5.0" -d "x=exec('ls')" "$TARGET/"
test_rule "POST passthru()" 403 -H "User-Agent: Mozilla/5.0" -d "x=passthru('id')" "$TARGET/"
test_rule "POST shell_exec()" 403 -H "User-Agent: Mozilla/5.0" -d "x=shell_exec('whoami')" "$TARGET/"
test_rule "POST child_process" 403 -H "User-Agent: Mozilla/5.0" -d "x=require('child_process')" "$TARGET/"
test_rule "POST SSTI" 403 -H "User-Agent: Mozilla/5.0" -d 'x={{__class__}}' "$TARGET/"
test_rule 'POST $eq(' 403 -H "User-Agent: Mozilla/5.0" -d 'x=$eq(1)' "$TARGET/"
test_rule 'POST $where(' 403 -H "User-Agent: Mozilla/5.0" -d 'x=$where(1==1)' "$TARGET/"
test_rule 'POST $_GET' 403 -H "User-Agent: Mozilla/5.0" -d 'x=$_GET[cmd]' "$TARGET/"
test_rule 'POST $_POST' 403 -H "User-Agent: Mozilla/5.0" -d 'y=$_POST[data]' "$TARGET/"
test_rule "POST javascript:" 403 -H "User-Agent: Mozilla/5.0" -d "q=javascript:alert(1)" "$TARGET/"
test_rule "POST document.cookie" 403 -H "User-Agent: Mozilla/5.0" -d "q=document.cookie" "$TARGET/"
echo "" | tee -a $RESULTS

# 8. 正常 POST (nginx 静态 root 返回 405)
echo -e "${CYAN}=== 8. 正常 POST（expect 405 static root）===${NC}" | tee -a $RESULTS
test_rule "Normal POST 1" 405 -H "User-Agent: Mozilla/5.0" -d "action=login&token=abc123def456" "$TARGET/"
test_rule "Normal POST 2" 405 -H "User-Agent: Mozilla/5.0" -d "message=hello_world_data_padding" "$TARGET/"
echo "" | tee -a $RESULTS

# 9. 文件上传检测 (fileext.rule)
echo -e "${CYAN}=== 9. 文件上传检测 (fileext.rule) ===${NC}" | tee -a $RESULTS
echo -e "${YELLOW}  --- 应拦截 403 ---${NC}" | tee -a $RESULTS
for ext in sql htaccess env bak log tmp swp gitignore config htpasswd; do
    echo "hello" | ssh 192.168.2.180 "cat > /tmp/test.$ext"
    code=$(ssh 192.168.2.180 "curl --globoff -s -m 5 -o /dev/null -w '%{http_code}' -H 'User-Agent: Mozilla/5.0' -F 'file=@/tmp/test.$ext' http://127.0.0.1:80/")
    if [ "$code" = "403" ]; then ok "Upload .$ext" "$code"; else bad "Upload .$ext" "$code" "403"; fi
done
echo -e "${YELLOW}  --- 应放行 (non-403) ---${NC}" | tee -a $RESULTS
for ext in txt jpg png pdf; do
    echo "hello" | ssh 192.168.2.180 "cat > /tmp/test.$ext"
    code=$(ssh 192.168.2.180 "curl --globoff -s -m 5 -o /dev/null -w '%{http_code}' -H 'User-Agent: Mozilla/5.0' -F 'file=@/tmp/test.$ext' http://127.0.0.1:80/")
    if [ "$code" != "403" ]; then ok "Upload .$ext" "$code"; else bad "Upload .$ext" "$code" "non-403"; fi
done
echo "" | tee -a $RESULTS

# 10. 白名单 IP / XFF 信任链 / trust_proxy_headers
echo -e "${CYAN}=== 10. 白名单 IP / XFF 信任链 / trust_proxy_headers ===${NC}" | tee -a $RESULTS

# 10a. 白名单 IP 通过 XFF 放行 (cdnip.rule 包含内网 IP → XFF 被信任)
# 10a. 非白名单 IP 通过 XFF 请求 SQLi → 应拦截 (XFF 被信任，拿到非白名单 IP，SQLi 拦截)
code=$(curl --globoff -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 1.2.3.4" "$TARGET/?id=union+select")
if [ "$code" = "403" ]; then ok "XFF非白名单IP 1.2.3.4 + SQLi 拦截" "$code"; else bad "XFF非白名单IP 1.2.3.4 + SQLi" "$code" "403"; fi

# 10b. 白名单 IP 通过 XFF 放行
code=$(curl --globoff -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 8.8.8.8" "$TARGET/?id=union+select")
if [ "$code" = "200" ]; then ok "XFF白名单IP 8.8.8.8 放行" "$code"; else bad "XFF白名单IP 8.8.8.8" "$code" "200"; fi

# 10c. 临时移除 cdnip.rule → XFF 被无条件信任 → 白名单 IP 放行
$SSH180 "mv /opt/nginx/lua/waf/rule-config/cdnip.rule /opt/nginx/lua/waf/rule-config/cdnip.rule.bak 2>/dev/null"
sleep 3
$SSH180 "$NGINX_CMD -s reload 2>&1"
sleep 2
code=$(curl --globoff -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 8.8.8.8" "$TARGET/?id=union+select")
if [ "$code" = "200" ]; then ok "无 cdnip.rule: XFF白名单IP 8.8.8.8 放行" "$code"; else bad "无 cdnip.rule: XFF白名单IP 8.8.8.8" "$code" "200"; fi
# 10d. 无 cdnip.rule → 非白名单 IP + SQLi → 应拦截
code=$(curl --globoff -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 1.2.3.4" "$TARGET/?id=union+select")
if [ "$code" = "403" ]; then ok "无 cdnip.rule: XFF非白名单IP 1.2.3.4 + SQLi 拦截" "$code"; else bad "无 cdnip.rule: XFF非白名单IP 1.2.3.4 + SQLi" "$code" "403"; fi
# 恢复 cdnip.rule
$SSH180 "mv /opt/nginx/lua/waf/rule-config/cdnip.rule.bak /opt/nginx/lua/waf/rule-config/cdnip.rule 2>/dev/null"
sleep 3
$SSH180 "$NGINX_CMD -s reload 2>&1"
sleep 2

# 10e. trust_proxy_headers=off → 不信任 XFF，用 remote_addr → SQLi 拦截
set_config "trust_proxy_headers" "off"
sleep 3
$SSH180 "$NGINX_CMD -s reload 2>&1"
sleep 2
code=$(curl --globoff -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 8.8.8.8" "$TARGET/?id=union+select")
if [ "$code" = "403" ]; then ok "trust_proxy_headers=off: XFF被忽略，SQLi拦截" "$code"; else bad "trust_proxy_headers=off: XFF被忽略" "$code" "403"; fi
# 10f. trust_proxy_headers=off → 不信任 XFF → 正常请求放行
code=$(curl --globoff -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 8.8.8.8" "$TARGET/")
if [ "$code" = "200" ]; then ok "trust_proxy_headers=off: 正常请求放行" "$code"; else bad "trust_proxy_headers=off: 正常请求" "$code" "200"; fi
# 恢复 trust_proxy_headers=on
set_config "trust_proxy_headers" "on"
sleep 3
$SSH180 "$NGINX_CMD -s reload 2>&1"
sleep 2
echo "" | tee -a $RESULTS

# 11. 白名单 URL
echo -e "${CYAN}=== 11. 白名单 URL ===${NC}" | tee -a $RESULTS
code=$(curl --globoff -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "$TARGET/123/")
if [ "$code" != "403" ]; then ok "White URL /123/" "$code"; else bad "White URL /123/" "$code" "non-403"; fi
echo "" | tee -a $RESULTS

# 12. Referer (off)
echo -e "${CYAN}=== 12. Referer (off) ===${NC}" | tee -a $RESULTS
code=$(curl --globoff -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -e "http://evil.pay.com/" "$TARGET/")
if [ "$code" = "200" ]; then ok "Referer .pay." "$code"; else bad "Referer .pay." "$code" "200"; fi
code=$(curl --globoff -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -e "http://evil.alipay.com/" "$TARGET/")
if [ "$code" = "200" ]; then ok "Referer .alipay." "$code"; else bad "Referer .alipay." "$code" "200"; fi
echo "" | tee -a $RESULTS

# 13. Location /nowaf/
echo -e "${CYAN}=== 13. Location /nowaf/ ===${NC}" | tee -a $RESULTS
code=$(curl --globoff -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "$TARGET/nowaf/")
if [ "$code" != "403" ]; then ok "Location /nowaf/ ok" "$code"; else bad "Location /nowaf/" "$code" "non-403"; fi
code=$(curl --globoff -s -m 5 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "$TARGET/nowaf/?id=1+union+select+1")
if [ "$code" != "403" ]; then ok "Location /nowaf/ SQLi pass" "$code"; else bad "Location /nowaf/ SQLi" "$code" "non-403"; fi
code=$(curl --globoff -s -m 5 -o /dev/null -w "%{http_code}" -A "sqlmap/1.0" "$TARGET/nowaf/")
if [ "$code" != "403" ]; then ok "Location /nowaf/ sqlmap UA pass" "$code"; else bad "Location /nowaf/ sqlmap UA" "$code" "non-403"; fi
echo "" | tee -a $RESULTS

# 14. 稳定性测试
echo -e "${CYAN}=== 14. 稳定性测试 ===${NC}" | tee -a $RESULTS
echo "  14a: 超长 URL (100KB)" | tee -a $RESULTS
LONG_URL=$(python3 -c "print('a'*100000)")
code=$(curl --globoff -s -m 10 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "$TARGET/?q=${LONG_URL}" 2>/dev/null)
ALIVE=$(curl --globoff -s -m 3 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "$TARGET/" 2>/dev/null)
if [ "$ALIVE" = "200" ] || [ "$ALIVE" = "403" ]; then ok "超长URL后存活($code)" "$ALIVE"; else bad "超长URL后崩溃" "$ALIVE" "200/403"; fi
echo "  14b: 大量 Cookie (500个)" | tee -a $RESULTS
COOKIES=""
for i in $(seq 1 500); do COOKIES="c$i=val$i; $COOKIES"; done
code=$(curl --globoff -s -m 10 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" -b "$COOKIES" "$TARGET/" 2>/dev/null)
ALIVE=$(curl --globoff -s -m 3 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "$TARGET/" 2>/dev/null)
if [ "$ALIVE" = "200" ] || [ "$ALIVE" = "403" ]; then ok "大量Cookie后存活($code)" "$ALIVE"; else bad "大量Cookie后崩溃" "$ALIVE" "200/403"; fi
echo "  14c: 1MB POST body" | tee -a $RESULTS
ssh 192.168.2.180 'dd if=/dev/zero bs=1M count=1 2>/dev/null | tr "\0" "a" > /tmp/body_1mb.txt'
code=$(ssh 192.168.2.180 "curl --globoff -s -m 10 -o /dev/null -w '%{http_code}' -H 'User-Agent: Mozilla/5.0' -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @/tmp/body_1mb.txt http://127.0.0.1:80/")
ALIVE=$(curl --globoff -s -m 3 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "$TARGET/" 2>/dev/null)
if [ "$ALIVE" = "200" ] || [ "$ALIVE" = "403" ]; then ok "1MB POST后存活($code)" "$ALIVE"; else bad "1MB POST后崩溃" "$ALIVE" "200/403"; fi
echo "" | tee -a $RESULTS

# 15. CC 攻击测试
echo -e "${CYAN}=== 15. CC 攻击测试 ===${NC}" | tee -a $RESULTS
echo "  临时开启 CC 检测..." | tee -a $RESULTS
set_config "cc_check" "on"
$SSH180 "$NGINX_CMD -s reload 2>&1"
sleep 3
echo "  临时设置 cc_rate=60/60 方便测试" | tee -a $RESULTS
set_config "cc_rate" "60/60"
echo "  发送 80 个请求 (cc_rate=60/60)" | tee -a $RESULTS
CC_PASS=0; CC_BLOCK=0
for i in $(seq 1 80); do
    CODE=$(curl --globoff -s -m 3 -o /dev/null -w "%{http_code}" -H "User-Agent: Mozilla/5.0" "$TARGET/")
    if [ "$CODE" = "403" ]; then CC_BLOCK=$((CC_BLOCK+1)); else CC_PASS=$((CC_PASS+1)); fi
done
echo "  CC: 放行 $CC_PASS 次, 拦截 $CC_BLOCK 次" | tee -a $RESULTS
if [ "$CC_BLOCK" -gt 0 ]; then ok "CC 检测触发" "403"; else bad "CC 检测未触发" "0" "403"; fi
echo "" | tee -a $RESULTS

# 16. NginxGuard 日志检查
echo -e "${CYAN}=== 16. NginxGuard 日志检查 ===${NC}" | tee -a $RESULTS
LOGFILE="$WAF_LOG_DIR/$(date +%Y-%m-%d)_waf.log"
if [ -f "$LOGFILE" ]; then
    echo "  日志文件: $LOGFILE" | tee -a $RESULTS
    echo "  日志条数: $(wc -l < $LOGFILE)" | tee -a $RESULTS
    echo "  --- 按攻击类型统计 ---" | tee -a $RESULTS
    ssh 192.168.2.180 "cat $LOGFILE" | python3 -c "import sys,json\nfrom collections import Counter\nm=Counter()\nfor l in sys.stdin:\n try:\n  d=json.loads(l.strip())\n  m[d.get('attack_method','unknown')]+=1\n except:pass\nfor k,v in m.most_common():print(f'    {k}: {v}次')" 2>/dev/null | tee -a $RESULTS || echo "  (日志解析跳过)" | tee -a $RESULTS
    echo "  --- 最后3条日志 ---" | tee -a $RESULTS
    ssh 192.168.2.180 "tail -3 $LOGFILE" 2>/dev/null | tee -a $RESULTS || true
else
    echo "  未找到日志文件" | tee -a $RESULTS
fi
echo "" | tee -a $RESULTS

# 后处理: 恢复 CC + 重启 nginx
echo -e "${CYAN}=== 后处理: 恢复 CC + 重启 nginx ===${NC}" | tee -a $RESULTS
set_config "cc_check" "on"
set_config "cc_rate" "150/60"
$SSH180 "kill -TERM \$(cat /opt/nginx/logs/nginx.pid) 2>/dev/null; sleep 1; cd /opt/nginx && ./nginx -p /opt/nginx/ -c conf/nginx.conf 2>&1"
sleep 2
log "CC 检测已恢复, nginx 已重启清除封禁"
echo "" | tee -a $RESULTS

# 汇总
echo "========================================" | tee -a $RESULTS
echo "  测试结果汇总" | tee -a $RESULTS
echo "  PASS: $PASS  FAIL: $FAIL  TOTAL: $TOTAL" | tee -a $RESULTS
echo "  时间: $(date)" | tee -a $RESULTS
echo "========================================" | tee -a $RESULTS
if [ $FAIL -gt 0 ]; then
    echo -e "失败项:$ERRORS" | tee -a $RESULTS
fi
echo ""
echo "Results saved to $RESULTS"
