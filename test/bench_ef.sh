#!/bin/bash
# 补跑场景 E/F: trust_proxy_headers=on + 带XFF头
# 在 192.168.2.180 本地执行

WAF_CONFIG="/opt/nginx/lua/waf/config.lua"
RULE_DIR="/opt/nginx/lua/waf/rule-config"
RESULT_FILE="/tmp/bench_ef.txt"
> $RESULT_FILE

cp $WAF_CONFIG ${WAF_CONFIG}.bak_ef
sed -i 's|^config_cc_check = .*|config_cc_check = "off"|' $WAF_CONFIG
sed -i 's|^config_trust_proxy_headers = .*|config_trust_proxy_headers = "on"|' $WAF_CONFIG

restart_nginx() {
    kill -TERM $(cat /opt/nginx/logs/nginx.pid) 2>/dev/null; sleep 2
    cd /opt/nginx && ./nginx -p /opt/nginx/ -c conf/nginx.conf 2>&1; sleep 2
}

echo "===== 场景 E: proxy=on + cdnip.rule + 带XFF头 =====" | tee -a $RESULT_FILE
restart_nginx
for i in 1 2 3; do
    sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
    ab -n 1000 -c 50 -k -H "User-Agent: Mozilla/5.0" http://127.0.0.1/ >/dev/null 2>&1
    ab -n 30000 -c 100 -k -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 1.2.3.4" http://127.0.0.1/ 2>&1 | grep -E "Requests per second|Time per request.*mean|Failed requests" | tee -a $RESULT_FILE
    echo "---" | tee -a $RESULT_FILE
done

echo "" | tee -a $RESULT_FILE
echo "===== 场景 F: proxy=on + 无cdnip.rule + 带XFF头 =====" | tee -a $RESULT_FILE
mv $RULE_DIR/cdnip.rule $RULE_DIR/cdnip.rule.bak_ef 2>/dev/null
restart_nginx
for i in 1 2 3; do
    sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
    ab -n 1000 -c 50 -k -H "User-Agent: Mozilla/5.0" http://127.0.0.1/ >/dev/null 2>&1
    ab -n 30000 -c 100 -k -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 1.2.3.4" http://127.0.0.1/ 2>&1 | grep -E "Requests per second|Time per request.*mean|Failed requests" | tee -a $RESULT_FILE
    echo "---" | tee -a $RESULT_FILE
done

# 恢复
mv $RULE_DIR/cdnip.rule.bak_ef $RULE_DIR/cdnip.rule 2>/dev/null
cp ${WAF_CONFIG}.bak_ef $WAF_CONFIG
rm -f ${WAF_CONFIG}.bak_ef
restart_nginx
echo "===== 恢复完成 =====" | tee -a $RESULT_FILE
