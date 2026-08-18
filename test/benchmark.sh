#!/bin/bash
# NginxGuard 全场景压测 — 在 192.168.2.180 上本地执行
# 50000请求 200并发, 每场景3次取最佳值, ab + ps/top 监控
# 参考 waf_bench3.sh 的采样方式 (ps aux RSS + top CPU)

NGINX_HOME="/opt/nginx"
NGINX_BIN="$NGINX_HOME/./nginx"
WAF_CONFIG="$NGINX_HOME/lua/waf/config.lua"
NGINX_CONF="$NGINX_HOME/conf/nginx.conf"
TARGET="http://127.0.0.1:80/"
REQUESTS=50000
CONCURRENCY=200
UA="User-Agent: Mozilla/5.0"
RESULT_FILE="/tmp/bench_nginxguard.txt"
> $RESULT_FILE

# 压测前注释掉 limit_conn (限制并发连接数会干扰压测结果)
# 并调大 open_file_cache 有效期避免频繁过期
prepare_nginx_conf() {
    cp $NGINX_CONF ${NGINX_CONF}.bak
    sed -i 's/^\([[:space:]]*\)limit_conn addr/#\1limit_conn addr/' $NGINX_CONF
    sed -i 's/open_file_cache max=100000 inactive=20s/open_file_cache max=100000 inactive=300s/' $NGINX_CONF
    sed -i 's/open_file_cache_valid 30s/open_file_cache_valid 300s/' $NGINX_CONF
}

restore_nginx_conf() {
    [ -f ${NGINX_CONF}.bak ] && cp ${NGINX_CONF}.bak $NGINX_CONF
}

restart_nginx() {
    $NGINX_BIN -p $NGINX_HOME/ -c conf/nginx.conf -s stop 2>/dev/null || kill -TERM $(cat $NGINX_HOME/logs/nginx.pid 2>/dev/null) 2>/dev/null || true
    sleep 2
    cd $NGINX_HOME
    ./nginx -p $NGINX_HOME/ -c conf/nginx.conf 2>&1
    sleep 2
}

reload_nginx() {
    cd $NGINX_HOME
    $NGINX_BIN -p $NGINX_HOME/ -c conf/nginx.conf -s reload 2>&1
    sleep 3
}

set_config() {
    sed -i "s|^config_$1 = .*|config_$1 = \"$2\"|" $WAF_CONFIG
}

# 取 worker RSS (ps aux $6 = RSS KB) 和峰值 CPU (top $9)
# 在 ab 压测期间采样
run_bench() {
    local label="$1"
    local extra_args="$2"
    local best_rps=0; local best_p99=0; local best_cpu=0; local best_mem=0

    for i in 1 2 3; do
        restart_nginx
        sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
        sleep 1

        # 预热
        ab -n 1000 -c 50 -k -H "$UA" http://127.0.0.1/ >/dev/null 2>&1

        # ab 压测在后台跑, 同时采样 CPU
        ab -n $REQUESTS -c $CONCURRENCY -k -e /tmp/ab_stats.csv -H "$UA" $extra_args "$TARGET" > /tmp/ab_out.txt 2>&1 &
        local ab_pid=$!
        sleep 0.5
        # 采样 CPU 3 次
        cpu1=$(top -bn1 | grep "nginx" | grep -v grep | awk '{sum+=$9} END {print sum+0}')
        sleep 0.3
        cpu2=$(top -bn1 | grep "nginx" | grep -v grep | awk '{sum+=$9} END {print sum+0}')
        sleep 0.3
        cpu3=$(top -bn1 | grep "nginx" | grep -v grep | awk '{sum+=$9} END {print sum+0}')
        wait $ab_pid

        # 平均 CPU
        local cpu=$(echo "scale=0; ($cpu1 + $cpu2 + $cpu3 + 1) / 3" | bc 2>/dev/null || echo "$cpu1")

        # 解析 ab 结果
        local rps=$(grep "Requests per second" /tmp/ab_out.txt | awk '{print $4}')
        local tpr=$(grep "Time per request.*mean" /tmp/ab_out.txt | head -1 | awk '{print $4}')
        local p99=$(awk -F, 'NR==102{printf "%.0f", $2}' /tmp/ab_stats.csv 2>/dev/null)
        local fail=$(grep "Failed requests" /tmp/ab_out.txt | awk '{print $3}')
        [ -z "$fail" ] && fail=0

        # RSS: 所有 nginx worker 进程 (ps aux $6 = RSS KB)
        local rss=$(ps aux | grep "nginx: worker" | grep -v grep | awk '{sum+=$6} END {printf "%.0f", sum/1024}')
        [ -z "$rss" ] && rss="?"

        echo "  Run $i: RPS=${rps} TPR=${tpr}ms P99=${p99}ms CPU=${cpu}% RSS=${rss}MB Fail=${fail}" | tee -a $RESULT_FILE

        if [ -n "$rps" ] && [ "$(echo "$rps > $best_rps" | bc 2>/dev/null)" = "1" -o $i -eq 1 ]; then
            best_rps=$rps; best_p99=$p99; best_cpu=$cpu; best_mem=$rss
        fi
    done
    echo "  >>> BEST: RPS=${best_rps} P99=${best_p99}ms CPU=${best_cpu}% RSS=${best_mem}MB" | tee -a $RESULT_FILE
    echo "${label}|${best_rps}|${best_p99}|${best_cpu}|${best_mem}" >> /tmp/bench_data.txt
    echo "" | tee -a $RESULT_FILE
}

echo "========================================" | tee -a $RESULT_FILE
echo "  NginxGuard 全场景压测" | tee -a $RESULT_FILE
echo "  $(date '+%Y-%m-%d %H:%M:%S')" | tee -a $RESULT_FILE
echo "  Requests=$REQUESTS Concurrency=$CONCURRENCY KeepAlive" | tee -a $RESULT_FILE
echo "========================================" | tee -a $RESULT_FILE
echo "" | tee -a $RESULT_FILE
> /tmp/bench_data.txt

# POST data
echo "test=hello_world_data_padding_padding_padding" > /tmp/post_data.txt

# 备份原始配置
prepare_nginx_conf
cp $WAF_CONFIG ${WAF_CONFIG}.prod

# 场景 A: WAF 全关（基线）— lua_package_path 等保留不动, 仅 config_waf_enable=off
echo "######## A: WAF 全关（基线）########" | tee -a $RESULT_FILE
cp ${WAF_CONFIG}.prod $WAF_CONFIG
set_config "waf_enable" "off"
restart_nginx
run_bench "A-baseline" ""

# 场景 B: WAF 全开（无 CC/POST）
echo "######## B: WAF 全开（无 CC）########" | tee -a $RESULT_FILE
cp ${WAF_CONFIG}.prod $WAF_CONFIG
set_config "cc_check" "off"
set_config "post_check" "off"
set_config "cc_rate" "99999/60"
restart_nginx
run_bench "B-noCC" ""

# 场景 C: WAF + CC（POST 关闭）
echo "######## C: WAF + CC ########" | tee -a $RESULT_FILE
cp ${WAF_CONFIG}.prod $WAF_CONFIG
set_config "post_check" "off"
restart_nginx
run_bench "C-withCC" ""

# 场景 D: WAF + POST（CC 关闭）
echo "######## D: WAF + POST ########" | tee -a $RESULT_FILE
cp ${WAF_CONFIG}.prod $WAF_CONFIG
set_config "cc_check" "off"
restart_nginx
run_bench "D-withPOST" "-p /tmp/post_data.txt -T application/x-www-form-urlencoded"

# 场景 E: WAF 全开（生产配置）
echo "######## E: WAF 全开（生产）########" | tee -a $RESULT_FILE
cp ${WAF_CONFIG}.prod $WAF_CONFIG
restart_nginx
run_bench "E-production" "-p /tmp/post_data.txt -T application/x-www-form-urlencoded"

# 恢复生产配置
cp ${WAF_CONFIG}.prod $WAF_CONFIG
rm -f ${WAF_CONFIG}.prod
restore_nginx_conf
restart_nginx

echo "========================================" | tee -a $RESULT_FILE
echo "  压测完成: $(date)" | tee -a $RESULT_FILE
echo "========================================" | tee -a $RESULT_FILE
