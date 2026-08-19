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
AB_OUT="/tmp/ab_out_proxy.$$"
AB_STATS="/tmp/ab_stats_proxy.$$.csv"
WAF_CONFIG_BAK="${WAF_CONFIG}.bak_proxy.$$"
CDNIP_BAK="${RULE_DIR}/cdnip.rule.bak_bench.$$"
CLEANED_UP=0
BASELINE_TPR=""
> $RESULT_FILE

set_config() { $SSH "sed -i \"s|^config_$1 = .*|config_$1 = \\\"$2\\\"|\" $WAF_CONFIG"; }
restart_nginx() { $SSH "kill -TERM \$(cat /opt/nginx/logs/nginx.pid) 2>/dev/null; sleep 1; cd /opt/nginx && ./nginx -p /opt/nginx/ -c conf/nginx.conf 2>&1"; sleep 2; }

restore_cdnip() {
    $SSH "[ -f \"$CDNIP_BAK\" ] && mv \"$CDNIP_BAK\" \"$RULE_DIR/cdnip.rule\" || true"
}

cleanup() {
    if [ "$CLEANED_UP" -eq 1 ]; then
        return
    fi
    CLEANED_UP=1
    $SSH "if [ -f \"$WAF_CONFIG_BAK\" ]; then cp \"$WAF_CONFIG_BAK\" \"$WAF_CONFIG\"; rm -f \"$WAF_CONFIG_BAK\"; fi" || true
    restore_cdnip
    rm -f "$AB_OUT" "$AB_STATS"
    restart_nginx >/dev/null 2>&1 || true
}

trap cleanup EXIT INT TERM

run_bench() {
    local label="$1"
    shift
    local best_rps=""; local best_tpr=""; local best_p99=""; local best_cpu=""; local best_mem=""

    for i in 1 2 3; do
        restart_nginx
        $SSH "sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null" || true
        sleep 1
        # 预热
        ab -n 1000 -c 50 -k -H "$UA" http://192.168.2.180/ >/dev/null 2>&1
        # 压测
        ab -n $REQUESTS -c $CONCURRENCY -k -e "$AB_STATS" -H "$UA" "$@" "$TARGET" > "$AB_OUT" 2>&1 &
        local ab_pid=$!
        sleep 0.5
        cpu1=$(ssh 192.168.2.180 "top -bn1 | grep nginx | grep -v grep | awk '{sum+=\$9} END {print sum+0}'")
        sleep 0.3
        cpu2=$(ssh 192.168.2.180 "top -bn1 | grep nginx | grep -v grep | awk '{sum+=\$9} END {print sum+0}'")
        sleep 0.3
        cpu3=$(ssh 192.168.2.180 "top -bn1 | grep nginx | grep -v grep | awk '{sum+=\$9} END {print sum+0}'")
        wait $ab_pid
        local cpu=$(echo "scale=0; ($cpu1 + $cpu2 + $cpu3 + 1) / 3" | bc 2>/dev/null || echo "$cpu1")
        local rps=$(grep "Requests per second" "$AB_OUT" | awk '{print $4}')
        local tpr=$(grep "Time per request.*mean" "$AB_OUT" | head -1 | awk '{print $4}')
        local p99=$(awk -F, 'NR==102{printf "%.0f", $2}' "$AB_STATS" 2>/dev/null)
        local fail=$(grep "Failed requests" "$AB_OUT" | awk '{print $3}')
        [ -z "$fail" ] && fail=0
        local rss=$(ssh 192.168.2.180 "ps aux | grep 'nginx: worker' | grep -v grep | awk '{sum+=\$6} END {printf \"%.0f\", sum/1024}'")
        [ -z "$rss" ] && rss="?"
        echo "  Run $i: RPS=${rps} TPR=${tpr}ms P99=${p99}ms CPU=${cpu}% RSS=${rss}MB Fail=${fail}" | tee -a $RESULT_FILE
        if [ -n "$rps" ] && { [ -z "$best_rps" ] || [ "$(echo "$rps > $best_rps" | bc 2>/dev/null)" = "1" ]; }; then
            best_rps=$rps; best_tpr=$tpr; best_p99=$p99; best_cpu=$cpu; best_mem=$rss
        fi
    done
    if [ "$label" = "A-baseline" ]; then
        BASELINE_TPR="$best_tpr"
    fi
    local overhead="?"
    if [ -n "$BASELINE_TPR" ] && [ -n "$best_tpr" ]; then
        overhead=$(echo "scale=1; ($best_tpr - $BASELINE_TPR) / $BASELINE_TPR * 100" | bc 2>/dev/null || echo "?")
    fi
    echo "  >>> BEST: RPS=${best_rps} TPR=${best_tpr}ms P99=${best_p99}ms CPU=${best_cpu}% RSS=${best_mem}MB (TPR vs baseline ${overhead}%)" | tee -a $RESULT_FILE
    echo "" | tee -a $RESULT_FILE
}

# 备份配置
$SSH "cp $WAF_CONFIG $WAF_CONFIG_BAK"

echo "========================================" | tee -a $RESULT_FILE
echo "  NginxGuard trust_proxy_headers 对比压测" | tee -a $RESULT_FILE
echo "  $(date '+%Y-%m-%d %H:%M:%S')" | tee -a $RESULT_FILE
echo "  Target: $TARGET (4核, 23GB)" | tee -a $RESULT_FILE
echo "  Requests=$REQUESTS Concurrency=$CONCURRENCY KeepAlive" | tee -a $RESULT_FILE
echo "========================================" | tee -a $RESULT_FILE
echo "" | tee -a $RESULT_FILE

# 场景 A: WAF 全关 (基线)
echo "######## A: WAF 全关 (基线) ########" | tee -a $RESULT_FILE
$SSH "cp $WAF_CONFIG_BAK $WAF_CONFIG"
set_config "waf_enable" "off"
restart_nginx
run_bench "A-baseline"

# 场景 B: trust_proxy_headers=off
echo "######## B: trust_proxy_headers=off ########" | tee -a $RESULT_FILE
$SSH "cp $WAF_CONFIG_BAK $WAF_CONFIG"
set_config "cc_check" "off"
restart_nginx
run_bench "B-proxy-off"

# 场景 C: trust_proxy_headers=on + cdnip.rule 存在
echo "######## C: trust_proxy_headers=on + cdnip.rule 存在 ########" | tee -a $RESULT_FILE
$SSH "cp $WAF_CONFIG_BAK $WAF_CONFIG"
set_config "cc_check" "off"
restart_nginx
run_bench "C-proxy-on-cdnip"

# 场景 D: trust_proxy_headers=on + cdnip.rule 移除 (无条件信任 XFF)
echo "######## D: trust_proxy_headers=on + cdnip.rule 移除 ########" | tee -a $RESULT_FILE
$SSH "cp $WAF_CONFIG_BAK $WAF_CONFIG"
set_config "cc_check" "off"
$SSH "[ -f \"$RULE_DIR/cdnip.rule\" ] && mv \"$RULE_DIR/cdnip.rule\" \"$CDNIP_BAK\" || true"
restart_nginx
run_bench "D-proxy-on-nocdnip"
restore_cdnip

# 场景 E: trust_proxy_headers=on + 带伪造 XFF 头 (模拟真实 CDN 场景)
echo "######## E: trust_proxy_headers=on + 带XFF头 ########" | tee -a $RESULT_FILE
$SSH "cp $WAF_CONFIG_BAK $WAF_CONFIG"
set_config "cc_check" "off"
restart_nginx
run_bench "E-proxy-on-withxff" -H "X-Forwarded-For: 1.2.3.4"

echo "========================================" | tee -a $RESULT_FILE
echo "  压测完成: $(date)" | tee -a $RESULT_FILE
echo "========================================" | tee -a $RESULT_FILE

echo ""
echo "========== 结果汇总 =========="
grep "BEST" $RESULT_FILE
