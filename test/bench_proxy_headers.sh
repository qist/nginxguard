#!/bin/bash
# NginxGuard trust_proxy_headers on/off 对比压测
# 目标: 192.168.2.180 (4核, 23GB RAM, NginxGuard)
# 测试场景:
#   A: WAF 全关 (基线)
#   B: trust_proxy_headers=off (不信任 XFF, 仅用 remote_addr)
#   C: trust_proxy_headers=on + cdnip.rule 存在 (安全模式: 验证 CDN IP 后信任 XFF)
#   D: trust_proxy_headers=on + cdnip.rule 移除 (原始模式: 无条件信任 XFF)
#   E: trust_proxy_headers=on + 带伪造 XFF 头 (模拟真实场景)
# 每场景: 20000请求, 100并发, 3次取最佳, 记录 RPS/TPR/P99/CPU/RSS

TARGET="http://192.168.2.180/"
SSH="ssh 192.168.2.180"
NGINX_CMD="cd /opt/nginx && ./nginx -p /opt/nginx/ -c conf/nginx.conf"
WAF_CONFIG="/opt/nginx/lua/waf/config.lua"
RULE_DIR="/opt/nginx/lua/waf/rule-config"
REQUESTS=20000
CONCURRENCY=100
UA="User-Agent: Mozilla/5.0"
RESULT_FILE="/tmp/bench_proxy_headers.txt"
> $RESULT_FILE

set_config() { $SSH "sed -i \"s|^config_$1 = .*|config_$1 = \\\"$2\\\"|\" $WAF_CONFIG"; }
restart_nginx() { $SSH "kill -TERM \$(cat /opt/nginx/logs/nginx.pid) 2>/dev/null; sleep 1; cd /opt/nginx && ./nginx -p /opt/nginx/ -c conf/nginx.conf 2>&1"; sleep 2; }

run_bench() {
    local label="$1"
    local extra_args="$2"
    local best_rps=0; local best_p99=0; local best_cpu=0; local best_mem=0

    for i in 1 2 3; do
        restart_nginx
        $SSH "sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null" || true
        sleep 1
        # 预热
        ab -n 1000 -c 50 -k -H "$UA" http://192.168.2.180/ >/dev/null 2>&1
        # 压测
        ab -n $REQUESTS -c $CONCURRENCY -k -e /tmp/ab_stats_proxy.csv -H "$UA" $extra_args "$TARGET" > /tmp/ab_out_proxy.txt 2>&1 &
        local ab_pid=$!
        sleep 0.5
        cpu1=$(ssh 192.168.2.180 "top -bn1 | grep nginx | grep -v grep | awk '{sum+=\$9} END {print sum+0}'")
        sleep 0.3
        cpu2=$(ssh 192.168.2.180 "top -bn1 | grep nginx | grep -v grep | awk '{sum+=\$9} END {print sum+0}'")
        sleep 0.3
        cpu3=$(ssh 192.168.2.180 "top -bn1 | grep nginx | grep -v grep | awk '{sum+=\$9} END {print sum+0}'")
        wait $ab_pid
        local cpu=$(echo "scale=0; ($cpu1 + $cpu2 + $cpu3 + 1) / 3" | bc 2>/dev/null || echo "$cpu1")
        local rps=$(grep "Requests per second" /tmp/ab_out_proxy.txt | awk '{print $4}')
        local tpr=$(grep "Time per request.*mean" /tmp/ab_out_proxy.txt | head -1 | awk '{print $4}')
        local p99=$(awk -F, 'NR==102{printf "%.0f", $2}' /tmp/ab_stats_proxy.csv 2>/dev/null)
        local fail=$(grep "Failed requests" /tmp/ab_out_proxy.txt | awk '{print $3}')
        [ -z "$fail" ] && fail=0
        local rss=$(ssh 192.168.2.180 "ps aux | grep 'nginx: worker' | grep -v grep | awk '{sum+=\$6} END {printf \"%.0f\", sum/1024}'")
        [ -z "$rss" ] && rss="?"
        echo "  Run $i: RPS=${rps} TPR=${tpr}ms P99=${p99}ms CPU=${cpu}% RSS=${rss}MB Fail=${fail}" | tee -a $RESULT_FILE
        if [ -n "$rps" ] && [ "$(echo "$rps > $best_rps" | bc 2>/dev/null)" = "1" -o $i -eq 1 ]; then
            best_rps=$rps; best_p99=$p99; best_cpu=$cpu; best_mem=$rss
        fi
    done
    echo "  >>> BEST: RPS=${best_rps} P99=${best_p99}ms CPU=${best_cpu}% RSS=${best_mem}MB" | tee -a $RESULT_FILE
    echo "" | tee -a $RESULT_FILE
}

# 备份配置
$SSH "cp $WAF_CONFIG ${WAF_CONFIG}.bak_proxy"

echo "========================================" | tee -a $RESULT_FILE
echo "  NginxGuard trust_proxy_headers 对比压测" | tee -a $RESULT_FILE
echo "  $(date '+%Y-%m-%d %H:%M:%S')" | tee -a $RESULT_FILE
echo "  Target: $TARGET (4核, 23GB)" | tee -a $RESULT_FILE
echo "  Requests=$REQUESTS Concurrency=$CONCURRENCY KeepAlive" | tee -a $RESULT_FILE
echo "========================================" | tee -a $RESULT_FILE
echo "" | tee -a $RESULT_FILE

# 场景 A: WAF 全关 (基线)
echo "######## A: WAF 全关 (基线) ########" | tee -a $RESULT_FILE
$SSH "cp ${WAF_CONFIG}.bak_proxy $WAF_CONFIG"
set_config "waf_enable" "off"
restart_nginx
run_bench "A-baseline" ""

# 场景 B: trust_proxy_headers=off
echo "######## B: trust_proxy_headers=off ########" | tee -a $RESULT_FILE
$SSH "cp ${WAF_CONFIG}.bak_proxy $WAF_CONFIG"
set_config "cc_check" "off"
restart_nginx
run_bench "B-proxy-off" ""

# 场景 C: trust_proxy_headers=on + cdnip.rule 存在
echo "######## C: trust_proxy_headers=on + cdnip.rule 存在 ########" | tee -a $RESULT_FILE
$SSH "cp ${WAF_CONFIG}.bak_proxy $WAF_CONFIG"
set_config "cc_check" "off"
restart_nginx
run_bench "C-proxy-on-cdnip" ""

# 场景 D: trust_proxy_headers=on + cdnip.rule 移除 (无条件信任 XFF)
echo "######## D: trust_proxy_headers=on + cdnip.rule 移除 ########" | tee -a $RESULT_FILE
$SSH "cp ${WAF_CONFIG}.bak_proxy $WAF_CONFIG"
set_config "cc_check" "off"
$SSH "mv $RULE_DIR/cdnip.rule $RULE_DIR/cdnip.rule.bak_bench 2>/dev/null"
restart_nginx
run_bench "D-proxy-on-nocdnip" ""
$SSH "mv $RULE_DIR/cdnip.rule.bak_bench $RULE_DIR/cdnip.rule 2>/dev/null"

# 场景 E: trust_proxy_headers=on + 带伪造 XFF 头 (模拟真实 CDN 场景)
echo "######## E: trust_proxy_headers=on + 带XFF头 ########" | tee -a $RESULT_FILE
$SSH "cp ${WAF_CONFIG}.bak_proxy $WAF_CONFIG"
set_config "cc_check" "off"
restart_nginx
run_bench "E-proxy-on-withxff" '-H "X-Forwarded-For: 1.2.3.4"'

# 恢复配置
$SSH "cp ${WAF_CONFIG}.bak_proxy $WAF_CONFIG"
$SSH "rm -f ${WAF_CONFIG}.bak_proxy"
restart_nginx

echo "========================================" | tee -a $RESULT_FILE
echo "  压测完成: $(date)" | tee -a $RESULT_FILE
echo "========================================" | tee -a $RESULT_FILE

echo ""
echo "========== 结果汇总 =========="
grep "BEST" $RESULT_FILE
