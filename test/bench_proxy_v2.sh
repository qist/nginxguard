#!/bin/bash
# NginxGuard 精准对比压测 v2 — 在 192.168.2.180 本地执行
# 消除网络延迟干扰，聚焦 Lua 代码执行开销
# 场景:
#   A: WAF 全关 (基线)
#   B: WAF 全开 + trust_proxy_headers=off (仅 remote_addr)
#   C: WAF 全开 + trust_proxy_headers=on + cdnip.rule 存在 (验证 CDN)
#   D: WAF 全开 + trust_proxy_headers=on + 无 cdnip.rule (无条件信任)
#   E: WAF 全开 + trust_proxy_headers=on + cdnip.rule + 带XFF头
#   F: WAF 全开 + trust_proxy_headers=on + cdnip.rule 移除 + 带XFF头

TARGET="http://127.0.0.1:80/"
WAF_CONFIG="/opt/nginx/lua/waf/config.lua"
RULE_DIR="/opt/nginx/lua/waf/rule-config"
NGINX_BIN="/opt/nginx/./nginx"
REQUESTS=30000
CONCURRENCY=100
UA="User-Agent: Mozilla/5.0"
RESULT_FILE="/tmp/bench_proxy_v2.txt"
AB_OUT="/tmp/ab_out_v2.$$"
AB_STATS="/tmp/ab_stats_v2.$$.csv"
WAF_CONFIG_BAK="${WAF_CONFIG}.bak_v2.$$"
CDNIP_BAK="${RULE_DIR}/cdnip.rule.bak_v2.$$"
CLEANED_UP=0
BASELINE_TPR=""
> $RESULT_FILE

set_config() { sed -i "s|^config_$1 = .*|config_$1 = \"$2\"|" $WAF_CONFIG; }
restart_nginx() {
    $NGINX_BIN -p /opt/nginx/ -c conf/nginx.conf -s stop 2>/dev/null || kill -TERM $(cat /opt/nginx/logs/nginx.pid 2>/dev/null) 2>/dev/null || true
    sleep 2
    cd /opt/nginx && ./nginx -p /opt/nginx/ -c conf/nginx.conf 2>&1
    sleep 2
}

restore_cdnip() {
    if [ -f "$CDNIP_BAK" ]; then
        mv "$CDNIP_BAK" "$RULE_DIR/cdnip.rule"
    fi
}

cleanup() {
    if [ "$CLEANED_UP" -eq 1 ]; then
        return
    fi
    CLEANED_UP=1
    if [ -f "$WAF_CONFIG_BAK" ]; then
        cp "$WAF_CONFIG_BAK" "$WAF_CONFIG"
        rm -f "$WAF_CONFIG_BAK"
    fi
    restore_cdnip
    rm -f "$AB_OUT" "$AB_STATS"
    restart_nginx >/dev/null 2>&1 || true
}

trap cleanup EXIT INT TERM

run_bench() {
    local label="$1"
    shift
    local best_rps=""; local best_tpr=""; local best_p99=""; local best_mem=""; local best_cpu=""

    for i in 1 2 3; do
        restart_nginx
        sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
        sleep 1
        # 预热
        ab -n 1000 -c 50 -k -H "$UA" http://127.0.0.1/ >/dev/null 2>&1
        # 压测
        ab -n $REQUESTS -c $CONCURRENCY -k -e "$AB_STATS" -H "$UA" "$@" "$TARGET" > "$AB_OUT" 2>&1 &
        local ab_pid=$!
        sleep 0.5
        # 采样 CPU + RSS
        cpu1=$(top -bn1 | grep "nginx" | grep -v grep | awk '{sum+=$9} END {print sum+0}')
        sleep 0.3
        cpu2=$(top -bn1 | grep "nginx" | grep -v grep | awk '{sum+=$9} END {print sum+0}')
        sleep 0.3
        cpu3=$(top -bn1 | grep "nginx" | grep -v grep | awk '{sum+=$9} END {print sum+0}')
        wait $ab_pid
        local cpu=$(echo "scale=0; ($cpu1 + $cpu2 + $cpu3 + 1) / 3" | bc 2>/dev/null || echo "$cpu1")
        local rps=$(grep "Requests per second" "$AB_OUT" | awk '{print $4}')
        local tpr=$(grep "Time per request.*mean" "$AB_OUT" | head -1 | awk '{print $4}')
        local p99=$(awk -F, 'NR==102{printf "%.0f", $2}' "$AB_STATS" 2>/dev/null)
        local fail=$(grep "Failed requests" "$AB_OUT" | awk '{print $3}')
        [ -z "$fail" ] && fail=0
        local rss=$(ps aux | grep "nginx: worker" | grep -v grep | awk '{sum+=$6} END {printf "%.0f", sum/1024}')
        [ -z "$rss" ] && rss="?"
        echo "  Run $i: RPS=${rps} TPR=${tpr}ms P99=${p99}ms CPU=${cpu}% RSS=${rss}MB Fail=${fail}" | tee -a $RESULT_FILE
        if [ -n "$rps" ] && { [ -z "$best_rps" ] || [ "$(echo "$rps > $best_rps" | bc 2>/dev/null)" = "1" ]; }; then
            best_rps=$rps; best_tpr=$tpr; best_p99=$p99; best_mem=$rss; best_cpu=$cpu
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
cp $WAF_CONFIG $WAF_CONFIG_BAK

echo "========================================" | tee -a $RESULT_FILE
echo "  NginxGuard trust_proxy_headers 精准压测 v2" | tee -a $RESULT_FILE
echo "  $(date '+%Y-%m-%d %H:%M:%S')" | tee -a $RESULT_FILE
echo "  Target: localhost (4核, 23GB)" | tee -a $RESULT_FILE
echo "  Requests=$REQUESTS Concurrency=$CONCURRENCY KeepAlive" | tee -a $RESULT_FILE
echo "========================================" | tee -a $RESULT_FILE
echo "" | tee -a $RESULT_FILE

# 场景 A: WAF 全关 (基线)
echo "######## A: WAF 全关 (基线) ########" | tee -a $RESULT_FILE
cp $WAF_CONFIG_BAK $WAF_CONFIG
set_config "waf_enable" "off"
restart_nginx
run_bench "A-baseline"

# 场景 B: trust_proxy_headers=off
echo "######## B: WAF全开 + trust_proxy_headers=off ########" | tee -a $RESULT_FILE
cp $WAF_CONFIG_BAK $WAF_CONFIG
set_config "cc_check" "off"
restart_nginx
run_bench "B-proxy-off"

# 场景 C: trust_proxy_headers=on + cdnip.rule 存在
echo "######## C: WAF全开 + trust_proxy_headers=on + cdnip.rule ########" | tee -a $RESULT_FILE
cp $WAF_CONFIG_BAK $WAF_CONFIG
set_config "cc_check" "off"
restart_nginx
run_bench "C-proxy-on-cdnip"

# 场景 D: trust_proxy_headers=on + 无 cdnip.rule
echo "######## D: WAF全开 + trust_proxy_headers=on + 无cdnip.rule ########" | tee -a $RESULT_FILE
cp $WAF_CONFIG_BAK $WAF_CONFIG
set_config "cc_check" "off"
if [ -f "$RULE_DIR/cdnip.rule" ]; then
    mv "$RULE_DIR/cdnip.rule" "$CDNIP_BAK"
fi
restart_nginx
run_bench "D-proxy-on-nocdnip"
restore_cdnip

# 场景 E: trust_proxy_headers=on + cdnip.rule + 带XFF头
echo "######## E: WAF全开 + trust_proxy_headers=on + cdnip + XFF头 ########" | tee -a $RESULT_FILE
cp $WAF_CONFIG_BAK $WAF_CONFIG
set_config "cc_check" "off"
restart_nginx
ab -n 100 -c 10 -H "User-Agent: Mozilla/5.0" -H "X-Forwarded-For: 1.2.3.4" http://127.0.0.1/ >/dev/null 2>&1
run_bench "E-proxy-on-xff" -H "X-Forwarded-For: 1.2.3.4"

# 场景 F: trust_proxy_headers=on + 无 cdnip.rule + 带XFF头
echo "######## F: WAF全开 + trust_proxy_headers=on + 无cdnip + XFF头 ########" | tee -a $RESULT_FILE
cp $WAF_CONFIG_BAK $WAF_CONFIG
set_config "cc_check" "off"
if [ -f "$RULE_DIR/cdnip.rule" ]; then
    mv "$RULE_DIR/cdnip.rule" "$CDNIP_BAK"
fi
restart_nginx
run_bench "F-proxy-on-nocdnip-xff" -H "X-Forwarded-For: 1.2.3.4"
restore_cdnip

echo "========================================" | tee -a $RESULT_FILE
echo "  压测完成: $(date)" | tee -a $RESULT_FILE
echo "========================================" | tee -a $RESULT_FILE

echo ""
echo "========== 结果汇总 =========="
grep "BEST" $RESULT_FILE
