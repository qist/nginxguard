#!/usr/bin/env resty
--NginxGuard 分段匹配缓存测试 (Bounded Segmented Match Cache)
--
--运行方式 (在 /opt/nginxguard 目录下):
--  resty test/test_match_cache.lua
--
--验证原则: 缓存只优化检测速度，绝不改变检测结果
--
--覆盖验收项:
--  T0 缓存关闭         : 关闭缓存时结果为 golden 基线，且不产生任何缓存写入
--  T1 缓存开启 A/B 一致: 同一批请求缓存开启/关闭逐请求比对，100% 一致
--                        (冷路径/暂存区命中/热点区命中三条路径均覆盖)
--  T2 4096 条填满      : 容量边界正常工作，只做部分淘汰，不清空
--  T3 100000 不同输入  : 不出现整体清空，统计始终有界
--  T4 热点穿插高基数   : 热点缓存条目在高基数洪水下完整保留
--  T5 恶意输入命中缓存 : 拦截结果与未缓存时一致
--  T6 热点区容量上限   : 批量淘汰触发，淘汰后结果与检测一致
--  T7 规则更新         : 旧规则缓存失效，按新规则检测
--  T8 缓存内部异常     : 正则执行失败不缓存为未命中，回退完整检测
--  T9 负结果晋升       : false 结果在暂存区/热点区间晋升传递不出错

local PASS, FAIL = 0, 0
local FAILURES = {}

local function check(name, cond, detail)
    if cond then
        PASS = PASS + 1
        print("  PASS  " .. name)
    else
        FAIL = FAIL + 1
        FAILURES[#FAILURES + 1] = name .. (detail and ("  [" .. detail .. "]") or "")
        print("  FAIL  " .. name .. (detail and ("  [" .. detail .. "]") or ""))
    end
end

local function section(title)
    print("")
    print("=== " .. title .. " ===")
end

-- ---------------------------------------------------------------------------
-- 环境: 定位 lib.lua / config.lua，重定向规则目录到临时目录
-- ---------------------------------------------------------------------------
local script_dir = (arg and arg[0] or ""):match("^(.*)[/\\]") or "."
package.path = script_dir .. "/../?.lua;" .. script_dir .. "/?.lua;" .. package.path

local RULE_DIR = "/tmp/nginxguard_cache_test_rules"
os.execute("mkdir -p " .. RULE_DIR)

require "config"
config_rule_dir = RULE_DIR          --重定向规则目录 (必须在首次 get_rule_entry 之前)
require "lib"

local stats = get_match_cache_stats

local function write_rule(name, lines)
    local f = io.open(RULE_DIR .. "/" .. name, "w")
    f:write(table.concat(lines, "\n") .. "\n")
    f:close()
end

--结果归一化: nil / "" / 规则字符串
local function norm(r)
    if r == nil then return "nil" end
    if r == "" then return "EMPTY" end
    return "MATCH:" .. r
end

local function match(rulefile, input, flags)
    return norm(match_any_rule(rulefile, input, flags))
end

-- ---------------------------------------------------------------------------
-- 测试规则文件 (正则需同时兼容 PCRE 与本机 Lua-pattern 桩)
-- ---------------------------------------------------------------------------
write_rule("ab.rule", {
    "# A/B 一致性测试规则",
    "unionselect",            --plain (fast 引擎)
    "etc/passwd",             --plain
    "alertscript",            --plain
    "evil[0-9]+payload",      --regex (combined 引擎)
    "select.+from",           --regex
})

write_rule("fill.rule", { "# 填充测试", "zznomatchhere" })
write_rule("pollute.rule", { "# 热点污染测试", "pollutesig" })
write_rule("falsepromote.rule", { "# 负结果晋升测试", "nothere_sig" })
write_rule("broken.rule", {
    "# 异常测试: 正则 + 坏正则 + 普通规则",
    "([unclosed",             --坏正则 (PCRE / Lua pattern 均编译失败)
    "brokensig",              --plain
})
write_rule("update.rule", { "# 规则更新测试", "oldsignature" })

local AB_INPUTS = {
    "hello world",                                        --benign
    "/index.html?id=123&name=test",                       --benign
    "Mozilla/5.0 (Windows NT 10.0)",                      --benign
    "unionselect",                                        --plain hit (exact)
    "xxx unionselect yyy",                                --plain hit (substring)
    "UNIONSELECT-UPPER-CASE",                             --plain hit (case-insensitive)
    "cat /etc/passwd please",                             --plain hit
    "<alertscript>tag</alertscript>",                     --plain hit
    "evil123payload",                                     --regex hit
    "evil99887766payload",                                --regex hit (longer)
    "select username from users",                         --regex hit
    "selesct username form users",                        --regex miss (负缓存)
    "normal text without any signature",                  --benign (负缓存)
    string.rep("a", 512),                                 --边界: 恰好 512 字节 (可缓存)
    string.rep("a", 512) .. "unionselect",                --边界内 + 攻击
    string.rep("b", 513),                                 --边界: 513 字节 (超过 INPUT_MAX, 不缓存)
    string.rep("b", 513) .. "unionselect",                --超边界 + 攻击 (仍必须检出)
    "quote\"and'semicolon;<>",                            --特殊字符
    "\1\2\3binary-ish\127",                               --控制字符
    "<",                                                  --小于 MIN_RULE_LEN (早退, 不缓存)
    "",                                                   --空串 (早退)
}

-- ---------------------------------------------------------------------------
section("T0 缓存关闭 → golden 基线")
config_match_cache = "off"
local golden = {}
for i, input in ipairs(AB_INPUTS) do
    golden[i] = match("ab.rule", input, "i")
end
check("缓存关闭时所有用例均有结果 (基线建立)", #golden == #AB_INPUTS)
local s0 = stats()
check("缓存关闭时不产生缓存写入", s0.hot == 0 and s0.probation == 0,
      "hot=" .. s0.hot .. " probation=" .. s0.probation)

-- ---------------------------------------------------------------------------
section("T1 缓存开启 A/B 逐请求 100% 一致 (冷路径/暂存命中/热点命中)")
config_match_cache = "on"
for pass = 1, 3 do
    local mismatches = 0
    for i, input in ipairs(AB_INPUTS) do
        local r = match("ab.rule", input, "i")
        if r ~= golden[i] then
            mismatches = mismatches + 1
            print("    mismatch pass" .. pass .. " case#" .. i ..
                  " cached=" .. r .. " golden=" .. golden[i])
        end
    end
    check("pass" .. pass .. " (pass1=冷检测入暂存, pass2=暂存命中晋升, pass3=热点命中): 与 golden 一致",
          mismatches == 0, mismatches .. " mismatches")
end
local s1 = stats()
check("缓存占用有界 (hot+probation <= 4096)", s1.hot + s1.probation <= 4096,
      "hot=" .. s1.hot .. " probation=" .. s1.probation)

-- ---------------------------------------------------------------------------
section("T2 4096 条缓存填满: 正常工作, 只部分淘汰不清空")
local fill_ok, fill_total = true, 4096
for i = 1, fill_total do
    local input = "fillcase" .. i .. "_unique_" .. (i * 7919)
    if match("fill.rule", input, "i") ~= "nil" then fill_ok = false end
end
check("4096 条不同输入全部完成检测且结果正确", fill_ok)
local s2 = stats()
check("填满后总占用不超过容量上限", s2.hot + s2.probation <= 4096,
      "hot=" .. s2.hot .. " probation=" .. s2.probation)
check("高基数洪水只停留在暂存区 (一次性输入不晋升热点)", s2.probation == s2.probation_cap,
      "probation=" .. s2.probation .. "/" .. s2.probation_cap)

-- ---------------------------------------------------------------------------
section("T3 连续 100000 个不同输入: 不出现整体清空")
local flood_ok = true
for i = 1, 100000 do
    local input = "flood" .. i .. "_padding_" .. (i * 7919)
    if i % 10000 == 0 then
        if match("fill.rule", input, "i") ~= "nil" then flood_ok = false end
        local s = stats()
        if s.hot + s.probation > 4096 then
            flood_ok = false
            print("    BOUND violation at " .. i .. ": hot=" .. s.hot .. " probation=" .. s.probation)
        end
    else
        match("fill.rule", input, "i")
    end
end
local s3 = stats()
check("100000 个不同输入处理完成且每万条抽检结果正确", flood_ok)
check("全程缓存占用有界 (无整体清空导致的异常状态)", s3.hot + s3.probation <= 4096,
      "hot=" .. s3.hot .. " probation=" .. s3.probation)

-- ---------------------------------------------------------------------------
section("T4 热点请求穿插高基数请求: 热点缓存保留")
--golden (缓存关闭)
config_match_cache = "off"
local HOT_N, FLOOD_N = 500, 20000
local hot_golden, flood_golden = {}, {}
for i = 1, HOT_N do
    local input = (i % 2 == 0) and ("hotcase" .. i .. " has pollutesig inside")
                  or ("hotcase" .. i .. " benign only")
    hot_golden[i] = { input, match("pollute.rule", input, "i") }
end
for i = 1, FLOOD_N do
    flood_golden[i] = match("pollute.rule", "floodcase" .. i .. "_" .. (i * 7919), "i")
end

--缓存开启: 热点条目命中两次 → 晋升热点区
config_match_cache = "on"
for i = 1, HOT_N do
    local input = hot_golden[i][1]
    match("pollute.rule", input, "i")
    match("pollute.rule", input, "i")
end
local s4a = stats()
check("500 个热点条目全部晋升热点区 (hot 增量 = 500)",
      s4a.hot - s3.hot == HOT_N, "hot delta=" .. (s4a.hot - s3.hot))

--洪水与热点请求穿插执行
local interleave_ok = true
for i = 1, FLOOD_N do
    match("pollute.rule", "floodcase" .. i .. "_" .. (i * 7919), "i")
    if i % 1000 == 0 then
        for j = 1, 50 do   --穿插命中 50 个热点条目
            local input = hot_golden[(i + j) % HOT_N + 1][1]
            match("pollute.rule", input, "i")
        end
    end
end
local s4b = stats()
check("高基数洪水期间热点区条目数不变 (热点未被冲刷)",
      s4b.hot == s4a.hot, "hot " .. s4a.hot .. " -> " .. s4b.hot)
check("洪水只占用暂存区", s4b.probation == s4b.probation_cap,
      "probation=" .. s4b.probation .. "/" .. s4b.probation_cap)

--逐条复核热点条目结果与 golden 一致 (含恶意输入命中缓存的拦截结果)
local hot_mismatch = 0
for i = 1, HOT_N do
    local r = match("pollute.rule", hot_golden[i][1], "i")
    if r ~= hot_golden[i][2] then hot_mismatch = hot_mismatch + 1 end
end
check("热点条目复核 100% 一致 (含恶意输入命中缓存的拦截结果)", hot_mismatch == 0,
      hot_mismatch .. " mismatches")

local flood_mismatch = 0
for i = 1, FLOOD_N, 500 do
    local r = match("pollute.rule", "floodcase" .. i .. "_" .. (i * 7919), "i")
    if r ~= flood_golden[i] then flood_mismatch = flood_mismatch + 1 end
end
check("洪水条目抽检与 golden 一致", flood_mismatch == 0, flood_mismatch .. " mismatches")

-- ---------------------------------------------------------------------------
section("T5 热点区容量上限: 批量淘汰触发, 淘汰不影响检测语义")
config_match_cache = "off"
local CAP_N = 3200
local cap_golden = {}
for i = 1, CAP_N do
    local input = "capcase" .. i .. "_pad_" .. (i * 6271)
    cap_golden[i] = { input, match("pollute.rule", input, "i") }
end
config_match_cache = "on"
for i = 1, CAP_N do
    local input = cap_golden[i][1]
    match("pollute.rule", input, "i")
    match("pollute.rule", input, "i")
end
local s5 = stats()
check("超过 3072 条后热点区触发批量淘汰 (hot <= cap)", s5.hot <= s5.hot_cap,
      "hot=" .. s5.hot .. "/" .. s5.hot_cap)
local cap_mismatch = 0
for i = 1, CAP_N do
    local r = match("pollute.rule", cap_golden[i][1], "i")
    if r ~= cap_golden[i][2] then cap_mismatch = cap_mismatch + 1 end
end
check("热点区淘汰后 3200 条复核 100% 一致 (淘汰条目回退完整检测)", cap_mismatch == 0,
      cap_mismatch .. " mismatches")

-- ---------------------------------------------------------------------------
section("T6 规则更新: 旧缓存失效, 按新规则检测")
config_match_cache = "on"
local UPD_OLD = "x oldsignature y"
local UPD_NEW = "x newsignature_here y"
local r_old_cached = match("update.rule", UPD_OLD, "i")
match("update.rule", UPD_OLD, "i")   --第二次命中 → 晋升热点
check("旧规则下检出 oldsignature", r_old_cached == "MATCH:oldsignature", r_old_cached)

write_rule("update.rule", { "# 规则更新测试 (v2, 更长的规则使文件大小变化)", "newsignature_here" })
print("  ... 等待规则缓存 TTL 过期 (" .. 11 .. "s)")
ngx.sleep(11)
local r_new = match("update.rule", UPD_NEW, "i")
local r_new_off  --golden: 关缓存复核
config_match_cache = "off"
r_new_off = match("update.rule", UPD_NEW, "i")
config_match_cache = "on"
check("规则更新后按新规则检出 newsignature_here", r_new == "MATCH:newsignature_here", r_new)
check("规则更新结果与缓存关闭时一致", r_new == r_new_off, r_new .. " vs " .. r_new_off)
local r_old_gone = match("update.rule", UPD_OLD, "i")
check("旧签名输入不再检出 (旧缓存 key 随 mtime 失效)", r_old_gone == "nil", r_old_gone)

-- ---------------------------------------------------------------------------
section("T7 缓存内部异常: 不缓存异常结果, 回退完整检测")
local s7a = stats()
--恶意输入命中缓存: 正常规则命中结果可缓存且一致
local r7_hit = match("broken.rule", "contains brokensig here", "i")
check("坏正则文件中的普通规则仍正常检出", r7_hit == "MATCH:brokensig", r7_hit)
local r7_hit2 = match("broken.rule", "contains brokensig here", "i")
check("命中缓存结果与首次一致", r7_hit2 == r7_hit, r7_hit2 .. " vs " .. r7_hit)

--坏正则触发异常: 结果返回 nil, 但绝不能缓存为未命中
local s7b = stats()
match("broken.rule", "no signature in this input at all", "i")
local s7c = stats()
check("正则异常输入的负结果未被缓存 (异常 → 回退完整检测)",
      s7c.hot == s7b.hot and s7c.probation == s7b.probation,
      "hot " .. s7b.hot .. "->" .. s7c.hot .. " probation " .. s7b.probation .. "->" .. s7c.probation)
local r7_err1 = match("broken.rule", "no signature in this input at all", "i")
local r7_err2 = match("broken.rule", "no signature in this input at all", "i")
check("异常输入重复请求仍走完整检测 (结果一致)", r7_err1 == r7_err2, r7_err1 .. " vs " .. r7_err2)
config_match_cache = "off"
local r7_golden = match("broken.rule", "no signature in this input at all", "i")
config_match_cache = "on"
check("异常输入结果与缓存关闭时一致", r7_err1 == r7_golden, r7_err1 .. " vs " .. r7_golden)

-- ---------------------------------------------------------------------------
section("T8 负结果 (false) 晋升: 暂存区 → 热点区传递正确")
local s8a = stats()
local fp = "falsepromote_case_" .. tostring(os.time())
local f1 = match("falsepromote.rule", fp, "i")
match("falsepromote.rule", fp, "i")   --暂存区命中 → 晋升 (value=false)
local f3 = match("falsepromote.rule", fp, "i")   --热点区命中 (false)
local s8b = stats()
check("负结果三次请求均为 nil (未匹配)", f1 == "nil" and f3 == "nil", f1 .. " / " .. f3)
check("负结果正确晋升至热点区 (hot 增量 = 1)", s8b.hot - s8a.hot == 1,
      "hot delta=" .. (s8b.hot - s8a.hot))

-- ---------------------------------------------------------------------------
section("T9 规则同秒双改: mtime 纳秒签名必须检出 (秒级 mtime 会漏检)")
config_match_cache = "on"
local SSD = RULE_DIR .. "/samesec.rule"
local f1 = io.open(SSD, "w"); f1:write("aaa_oldsignature\n"); f1:close()
local r_s1 = match("samesec.rule", "trigger aaa_oldsignature here", "i")
match("samesec.rule", "trigger aaa_oldsignature here", "i")   -- 二次命中 → 晋升热点
check("同秒双改前检出 oldsignature", r_s1 == "MATCH:aaa_oldsignature", r_s1)
-- 同一秒内重写 (内容与大小均变化): FFI 路径靠 mtime_nsec, fallback 路径靠 size
-- RULE_CACHE_TTL(10s) 内不 re-stat; TTL 过期后的 stat 必须检出 —— 秒级 mtime 方案下
-- 这次 stat 仍看到相同秒 → 永远漏检, 纳秒签名方案下必然检出 (本用例的核心回归点)
local f2 = io.open(SSD, "w"); f2:write("bbb_newsignature_here\n"); f2:close()
ngx.sleep(11)
local r_s2 = match("samesec.rule", "trigger aaa_oldsignature here", "i")
check("同秒双改后旧签名不再检出 (旧缓存随版本签名失效)", r_s2 == "nil", r_s2)
local r_s3 = match("samesec.rule", "trigger bbb_newsignature_here here", "i")
check("同秒双改后新签名被检出", r_s3 == "MATCH:bbb_newsignature_here", r_s3)

-- ---------------------------------------------------------------------------
section("T10 收尾: 缓存开启状态下全用例最终复核")
config_match_cache = "on"
local final_mismatch = 0
for i, input in ipairs(AB_INPUTS) do
    if match("ab.rule", input, "i") ~= golden[i] then final_mismatch = final_mismatch + 1 end
end
check("全部用例缓存开启状态最终复核 100% 一致", final_mismatch == 0, final_mismatch .. " mismatches")

-- ---------------------------------------------------------------------------
print("")
print("========================================")
print("  结果: PASS=" .. PASS .. "  FAIL=" .. FAIL)
if FAIL > 0 then
    print("  失败项:")
    for _, f in ipairs(FAILURES) do print("    - " .. f) end
end
print("========================================")
os.exit(FAIL == 0 and 0 or 1)
