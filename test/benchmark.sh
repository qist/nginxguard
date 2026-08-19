#!/bin/bash
# NginxGuard 全场景压测
# 默认在本机执行；如设置 BENCH_REMOTE_HOST=192.168.2.180，
# 则脚本会自动上传最新 access.lua/lib.lua/benchmark.sh 到远端，
# 替换远端 WAF 文件、校验并重启 nginx 后，再在远端本机执行压测。
# 50000请求 200并发, 每场景3次取最佳值, ab + ps/top 监控
# 为避免口径混乱，GET / form POST / JSON POST 分组分别对比。
# 参考 waf_bench3.sh 的采样方式 (ps aux RSS + top CPU)

REMOTE_HOST="${BENCH_REMOTE_HOST:-}"
REMOTE_TMP_SCRIPT="/tmp/benchmark_remote.$$.$RANDOM.sh"
REMOTE_TMP_ACCESS="/tmp/access_bench.$$.$RANDOM.lua"
REMOTE_TMP_LIB="/tmp/lib_bench.$$.$RANDOM.lua"
REMOTE_WAF_DIR="/opt/nginx/lua/waf"
REMOTE_NGINX_HOME="/opt/nginx"

if [ -n "$REMOTE_HOST" ] && [ "${BENCH_REMOTE_MODE:-0}" != "1" ]; then
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
    LOCAL_SCRIPT="$SCRIPT_DIR/benchmark.sh"
    LOCAL_ACCESS="$REPO_ROOT/access.lua"
    LOCAL_LIB="$REPO_ROOT/lib.lua"
    scp -o StrictHostKeyChecking=no "$LOCAL_SCRIPT" "${REMOTE_HOST}:${REMOTE_TMP_SCRIPT}" || exit 1
    scp -o StrictHostKeyChecking=no "$LOCAL_ACCESS" "${REMOTE_HOST}:${REMOTE_TMP_ACCESS}" || exit 1
    scp -o StrictHostKeyChecking=no "$LOCAL_LIB" "${REMOTE_HOST}:${REMOTE_TMP_LIB}" || exit 1
    ssh -o StrictHostKeyChecking=no "$REMOTE_HOST" "\
        install -m 644 '$REMOTE_TMP_ACCESS' '$REMOTE_WAF_DIR/access.lua' && \
        install -m 644 '$REMOTE_TMP_LIB' '$REMOTE_WAF_DIR/lib.lua' && \
        cd '$REMOTE_NGINX_HOME' && ./nginx -p '$REMOTE_NGINX_HOME/' -c conf/nginx.conf -t && \
        ./nginx -p '$REMOTE_NGINX_HOME/' -c conf/nginx.conf -s stop 2>/dev/null || kill -TERM \$(cat '$REMOTE_NGINX_HOME/logs/nginx.pid' 2>/dev/null) 2>/dev/null || true; \
        sleep 1; \
        cd '$REMOTE_NGINX_HOME' && ./nginx -p '$REMOTE_NGINX_HOME/' -c conf/nginx.conf >/dev/null 2>&1; \
        sleep 1; \
        chmod +x '$REMOTE_TMP_SCRIPT' && BENCH_REMOTE_MODE=1 '$REMOTE_TMP_SCRIPT'; \
        status=\$?; \
        rm -f '$REMOTE_TMP_SCRIPT' '$REMOTE_TMP_ACCESS' '$REMOTE_TMP_LIB'; \
        exit \$status"
    exit $?
fi

NGINX_HOME="/opt/nginx"
NGINX_BIN="$NGINX_HOME/./nginx"
WAF_CONFIG="$NGINX_HOME/lua/waf/config.lua"
NGINX_CONF="$NGINX_HOME/conf/nginx.conf"
TARGET="http://127.0.0.1:80/"
REQUESTS=50000
CONCURRENCY=200
UA="User-Agent: Mozilla/5.0"
RESULT_FILE="/tmp/bench_nginxguard.txt"
AB_OUT="/tmp/ab_out_bench.$$"
AB_STATS="/tmp/ab_stats_bench.$$.csv"
BENCH_DATA_FILE="/tmp/bench_data.$$"
FORM_POST_DATA_FILE="/tmp/post_form_data.$$"
JSON_POST_DATA_FILE="/tmp/post_json_data.$$"
WAF_CONFIG_BAK="${WAF_CONFIG}.prod.$$"
NGINX_CONF_BAK="${NGINX_CONF}.bak.$$"
CLEANED_UP=0
> $RESULT_FILE

# 压测前注释掉 limit_conn (限制并发连接数会干扰压测结果)
# 并调大 open_file_cache 有效期避免频繁过期
prepare_nginx_conf() {
    cp $NGINX_CONF $NGINX_CONF_BAK
    sed -i 's/^\([[:space:]]*\)limit_conn addr/#\1limit_conn addr/' $NGINX_CONF
    sed -i 's/open_file_cache max=100000 inactive=20s/open_file_cache max=100000 inactive=300s/' $NGINX_CONF
    sed -i 's/open_file_cache_valid 30s/open_file_cache_valid 300s/' $NGINX_CONF
}

restore_nginx_conf() {
    if [ -f "$NGINX_CONF_BAK" ]; then
        cp "$NGINX_CONF_BAK" "$NGINX_CONF"
        rm -f "$NGINX_CONF_BAK"
    fi
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

cleanup() {
    if [ "$CLEANED_UP" -eq 1 ]; then
        return
    fi
    CLEANED_UP=1
    if [ -f "$WAF_CONFIG_BAK" ]; then
        cp "$WAF_CONFIG_BAK" "$WAF_CONFIG"
        rm -f "$WAF_CONFIG_BAK"
    fi
    restore_nginx_conf
    rm -f "$AB_OUT" "$AB_STATS" "$BENCH_DATA_FILE" "$FORM_POST_DATA_FILE" "$JSON_POST_DATA_FILE"
    restart_nginx >/dev/null 2>&1 || true
}

trap cleanup EXIT INT TERM

# 取 worker RSS (ps aux $6 = RSS KB) 和峰值 CPU (top $9)
# 在 ab 压测期间采样
run_bench() {
    local label="$1"
    shift
    local best_rps=""; local best_tpr=""; local best_p99=""; local best_cpu=""; local best_mem=""

    for i in 1 2 3; do
        restart_nginx
        sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
        sleep 1

        # 预热：使用与正式压测相同的请求类型，避免 GET 预热 POST 场景
        ab -n 1000 -c 50 -k -H "$UA" "$@" "$TARGET" >/dev/null 2>&1

        # ab 压测在后台跑, 同时采样 CPU
        ab -n $REQUESTS -c $CONCURRENCY -k -e "$AB_STATS" -H "$UA" "$@" "$TARGET" > "$AB_OUT" 2>&1 &
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
        local rps=$(grep "Requests per second" "$AB_OUT" | awk '{print $4}')
        local tpr=$(grep "Time per request.*mean" "$AB_OUT" | head -1 | awk '{print $4}')
        local p99=$(awk -F, 'NR==102{printf "%.0f", $2}' "$AB_STATS" 2>/dev/null)
        local fail=$(grep "Failed requests" "$AB_OUT" | awk '{print $3}')
        [ -z "$fail" ] && fail=0

        # RSS: 所有 nginx worker 进程 (ps aux $6 = RSS KB)
        local rss=$(ps aux | grep "nginx: worker" | grep -v grep | awk '{sum+=$6} END {printf "%.0f", sum/1024}')
        [ -z "$rss" ] && rss="?"

        echo "  Run $i: RPS=${rps} TPR=${tpr}ms P99=${p99}ms CPU=${cpu}% RSS=${rss}MB Fail=${fail}" | tee -a $RESULT_FILE

        if [ -n "$rps" ] && { [ -z "$best_rps" ] || [ "$(echo "$rps > $best_rps" | bc 2>/dev/null)" = "1" ]; }; then
            best_rps=$rps; best_tpr=$tpr; best_p99=$p99; best_cpu=$cpu; best_mem=$rss
        fi
    done
    echo "  >>> BEST: RPS=${best_rps} TPR=${best_tpr}ms P99=${best_p99}ms CPU=${best_cpu}% RSS=${best_mem}MB" | tee -a $RESULT_FILE
    echo "${label}|${best_rps}|${best_tpr}|${best_p99}|${best_cpu}|${best_mem}" >> "$BENCH_DATA_FILE"
    echo "" | tee -a $RESULT_FILE
}

echo "========================================" | tee -a $RESULT_FILE
echo "  NginxGuard 全场景压测" | tee -a $RESULT_FILE
echo "  $(date '+%Y-%m-%d %H:%M:%S')" | tee -a $RESULT_FILE
echo "  Requests=$REQUESTS Concurrency=$CONCURRENCY KeepAlive" | tee -a $RESULT_FILE
echo "  对比口径: GET / form POST / JSON POST 各自独立" | tee -a $RESULT_FILE
echo "========================================" | tee -a $RESULT_FILE
echo "" | tee -a $RESULT_FILE
> "$BENCH_DATA_FILE"

# POST data
echo "test=hello_world_data_padding_padding_padding" > "$FORM_POST_DATA_FILE"
cat > "$JSON_POST_DATA_FILE" <<'EOF'
{"message":"hello_world_data_padding_padding_padding","id":123,"tags":["bench","json","post"]}
EOF

# 备份原始配置
prepare_nginx_conf
cp $WAF_CONFIG $WAF_CONFIG_BAK

echo "======== GET 场景 ========" | tee -a $RESULT_FILE
# 场景 A: GET 基线
echo "######## A: GET 基线（WAF 全关）########" | tee -a $RESULT_FILE
cp $WAF_CONFIG_BAK $WAF_CONFIG
set_config "waf_enable" "off"
restart_nginx
run_bench "A-baseline-get"

# 场景 B: GET + WAF（无 CC/POST）
echo "######## B: GET + WAF（无 CC/POST）########" | tee -a $RESULT_FILE
cp $WAF_CONFIG_BAK $WAF_CONFIG
set_config "cc_check" "off"
set_config "post_check" "off"
set_config "cc_rate" "99999/60"
restart_nginx
run_bench "B-get-noCC-noPOST"

# 场景 C: GET + WAF + CC（POST 关闭）
echo "######## C: GET + WAF + CC ########" | tee -a $RESULT_FILE
cp $WAF_CONFIG_BAK $WAF_CONFIG
set_config "post_check" "off"
restart_nginx
run_bench "C-get-withCC"

# 场景 D: GET + WAF 全开（生产）
echo "######## D: GET + WAF 全开（生产）########" | tee -a $RESULT_FILE
cp $WAF_CONFIG_BAK $WAF_CONFIG
restart_nginx
run_bench "D-get-production"

echo "======== Form POST 场景 ========" | tee -a $RESULT_FILE
# 场景 E: form POST 基线
echo "######## E: form POST 基线（WAF 全关）########" | tee -a $RESULT_FILE
cp $WAF_CONFIG_BAK $WAF_CONFIG
set_config "waf_enable" "off"
restart_nginx
run_bench "E-form-post-baseline" -p "$FORM_POST_DATA_FILE" -T application/x-www-form-urlencoded

# 场景 F: form POST + WAF（CC 关闭）
echo "######## F: form POST + WAF（CC 关闭）########" | tee -a $RESULT_FILE
cp $WAF_CONFIG_BAK $WAF_CONFIG
set_config "cc_check" "off"
restart_nginx
run_bench "F-form-post-withWAF" -p "$FORM_POST_DATA_FILE" -T application/x-www-form-urlencoded

echo "======== JSON POST 场景 ========" | tee -a $RESULT_FILE
# 场景 G: JSON POST 基线
echo "######## G: JSON POST 基线（WAF 全关）########" | tee -a $RESULT_FILE
cp $WAF_CONFIG_BAK $WAF_CONFIG
set_config "waf_enable" "off"
restart_nginx
run_bench "G-json-post-baseline" -p "$JSON_POST_DATA_FILE" -T application/json

# 场景 H: JSON POST + WAF（CC 关闭）
echo "######## H: JSON POST + WAF（CC 关闭）########" | tee -a $RESULT_FILE
cp $WAF_CONFIG_BAK $WAF_CONFIG
set_config "cc_check" "off"
restart_nginx
run_bench "H-json-post-withWAF" -p "$JSON_POST_DATA_FILE" -T application/json

echo "========================================" | tee -a $RESULT_FILE
echo "  压测完成: $(date)" | tee -a $RESULT_FILE
echo "========================================" | tee -a $RESULT_FILE
