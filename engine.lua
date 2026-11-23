-- NginxGuard 三层规则引擎
--  L1 基础检测: 由 access.lua 的 detect_* 注册为命名检测器, 每个请求最多执行一次
--  L2 组合规则: rule-config/combo.jsonl (JSONL, 一行一条, # 开头为注释)
--  L3 规则动作: BLOCK / LOG / ALERT / SCORE / CHALLENGE
--
-- 核心约束: 组合规则只消费 ngx.ctx 里已缓存的检测结果, 命中判断绝不重复执行底层扫描。
-- 检测器按需惰性执行 —— 组合规则引用到哪个才跑哪个, 未引用的零成本。
--
-- 表达式语法 (嵌套数组):
--   "url"                                  叶子: 检测器名 (见 access.lua 注册列表)
--   ["AND", a, b, ...]                     全部命中
--   ["OR", a, b, ...]                      任意命中
--   ["NOT", a]                             取反
--   ["AT_LEAST", n, a, b, ...]             至少 n 个命中
--   {"cond":"uri","op":"re","value":"^/x"} 内联条件 (不做规则扫描, 只读请求字段)
--
-- 内联条件 cond: uri / args / method / protocol / header / cookie / body /
--                ip / header_count / content_type / content_length /
--                transfer_encoding
-- 内联条件 op:   re (默认) / eq / contains / prefix / exists
--                header_count 专用: gte / lte / eq
-- 大小写:        re/contains/prefix/eq(非 method/protocol) 默认忽略大小写;
--                re 用 flags 或 case_sensitive:true 关闭, 其余用 icase:false 关闭
--
-- 规则字段:
--   id       规则标识 (必填, 写入日志 rule_tag)
--   if       表达式 (必填)
--   action   BLOCK(默认) / LOG / ALERT / SCORE / CHALLENGE
--   score    SCORE 动作的分值, 默认 10; 累计达到 config_score_block_threshold 时拦截
--            (阈值 0=只记分不拦截, 1=任意 SCORE 命中即拦, >1=累计达到才拦)
--   enabled  false 时跳过
--
-- 修改 combo.jsonl 后 10 秒内热加载, 无需改 Lua / reload。

local _M = {}

local cjson = require 'cjson'
local var = ngx.var
local re_find = ngx.re.find
local ngx_log = ngx.log
local ERR = ngx.ERR
local req_read_body = ngx.req.read_body
local req_get_body_data = ngx.req.get_body_data
local req_get_body_file = ngx.req.get_body_file
local req_get_headers = ngx.req.get_headers
local req_get_method = ngx.req.get_method
local string_sub = string.sub
local string_find = string.find
local string_lower = string.lower
local table_concat = table.concat
local type = type
local pairs = pairs
local ipairs = ipairs
local tostring = tostring
local tonumber = tonumber

local RULE_FILE = 'combo.jsonl'
local BODY_SCAN_LIMIT = 2097152
local HEADER_TEXT_MIN = 256
local HEADER_READ_MAX_CAP = 4096

local ACTIONS = { BLOCK = true, LOG = true, ALERT = true, SCORE = true, CHALLENGE = true }
local OPS = { AND = true, OR = true, NOT = true, AT_LEAST = true }

local detectors = {}

local compiled_rules = nil
local compiled_sig = nil
local header_read_max = HEADER_TEXT_MIN
local need_header_text = false
local UNKNOWN = {}

local INLINE_CONDS = {
    uri = true, args = true, method = true, protocol = true, header = true,
    cookie = true, body = true, ip = true, header_count = true,
    content_type = true, content_length = true, transfer_encoding = true,
}
local INLINE_OPS = { re = true, eq = true, contains = true, prefix = true, exists = true }
local HEADER_COUNT_OPS = { gte = true, lte = true, eq = true }

--=========================================================================
-- L1: 检测器注册与惰性执行
--=========================================================================
function _M.register(name, fn)
    detectors[name] = fn
end

-- 返回事实表 { rule=, detail=, tag= } 或 nil; 结果按请求缓存, 同一次请求不再执行
function _M.detect_state(name)
    local ctx = ngx.ctx
    local facts = ctx._waf_facts
    if facts == nil then
        facts = {}
        ctx._waf_facts = facts
    end
    local cached = facts[name]
    if cached ~= nil then
        if cached == UNKNOWN then return nil end
        return cached ~= false
    end

    local fn = detectors[name]
    if fn == nil then
        ngx_log(ERR, 'combo: unknown detector "', tostring(name), '"')
        facts[name] = UNKNOWN
        return nil
    end

    local ok, res = pcall(fn)
    if not ok then
        ngx_log(ERR, 'combo: detector "', name, '" failed: ', tostring(res))
        facts[name] = UNKNOWN
        return nil
    end
    if res == nil or res == false then
        facts[name] = false
        return false
    end
    if type(res) == 'boolean' then
        res = { rule = name }
    end
    facts[name] = res
    return true
end

-- Compatibility API for the traditional action path.
function _M.detect(name)
    if _M.detect_state(name) ~= true then return nil end
    return ngx.ctx._waf_facts[name]
end

--=========================================================================
-- 请求读取 (每请求只读一次)
--=========================================================================
local function get_body()
    local ctx = ngx.ctx
    local cached = ctx._waf_body
    if cached ~= nil then
        if cached == false then return nil, false end
        return cached.value, cached.complete
    end

    local ok = pcall(req_read_body)
    if not ok then
        ctx._waf_body = { value = nil, complete = false }
        return nil, false
    end

    local body_ok, body = pcall(req_get_body_data)
    if not body_ok then
        ctx._waf_body = { value = nil, complete = false }
        return nil, false
    end
    if body then
        local complete = #body <= BODY_SCAN_LIMIT
        if not complete then body = string_sub(body, 1, BODY_SCAN_LIMIT) end
        ctx._waf_body = { value = body, complete = complete }
        return body, complete
    end

    local file_ok, file = pcall(req_get_body_file)
    if not file_ok then
        ctx._waf_body = { value = nil, complete = false }
        return nil, false
    end
    if not file then
        ctx._waf_body = { value = '', complete = true }
        return '', true
    end
    local f = io.open(file, 'rb')
    if not f then
        ctx._waf_body = { value = nil, complete = false }
        return nil, false
    end
    local data, read_err = f:read(BODY_SCAN_LIMIT)
    if not data and read_err then
        f:close()
        ctx._waf_body = { value = nil, complete = false }
        return nil, false
    end
    data = data or ''
    local extra, extra_err = f:read(1)
    local complete = extra == nil and extra_err == nil
    f:close()
    ctx._waf_body = { value = data, complete = complete }
    return data, complete
end

local function get_header_info()
    local ctx = ngx.ctx
    local cached = ctx._waf_hdr
    if cached then return cached end

    local headers_ok, headers, err = pcall(req_get_headers, header_read_max)
    if not headers_ok then
        headers, err = nil, 'read_failed'
    end
    local count = 0
    local parts = need_header_text and {} or nil

    if headers then
        for k, v in pairs(headers) do
            if type(v) == 'table' then
                count = count + #v
                if parts then
                    for _, vv in ipairs(v) do
                        parts[#parts + 1] = k .. ': ' .. tostring(vv)
                    end
                end
            else
                count = count + 1
                if parts then parts[#parts + 1] = k .. ': ' .. tostring(v) end
            end
        end
    end
    local valid = err == nil or err == 'truncated'
    local complete = err == nil
    if err == 'truncated' then count = header_read_max end

    local info = { count = count, complete = complete, valid = valid }
    if parts then info.text = table_concat(parts, '\n') end
    ctx._waf_hdr = info
    return info
end

--=========================================================================
-- L2: 规则加载与表达式求值
--=========================================================================
local function to_pattern_list(v)
    if type(v) ~= 'table' then return nil end
    local out = {}
    for _, p in ipairs(v) do
        if type(p) == 'string' and #p > 0 then out[#out + 1] = p end
    end
    if #out == 0 then return nil end
    return out
end

local function validate_node(node, rid, depth, inside_not)
    if depth > 16 then
        ngx_log(ERR, 'combo: expression too deep in rule "', rid, '"')
        return false
    end
    local t = type(node)
    if t == 'string' then
        if not detectors[node] then
            ngx_log(ERR, 'combo: unknown detector "', node, '" in rule "', rid, '"')
            return false
        end
        if inside_not then
            ngx_log(ERR, 'combo: NOT cannot contain detector "', node, '" in rule "', rid, '"')
            return false
        end
        return true
    end
    if t ~= 'table' then return false end

    local op = node[1]
    if op ~= nil then
        if not OPS[op] then return false end
        if op == 'NOT' then
            return #node == 2 and validate_node(node[2], rid, depth + 1, true)
        end
        if op == 'AT_LEAST' then
            local need = tonumber(node[2])
            if not need or need < 1 or need == math.huge or need % 1 ~= 0
                or #node < 3 or need > #node - 2 then return false end
            for i = 3, #node do
                if not validate_node(node[i], rid, depth + 1, inside_not) then return false end
            end
            return true
        end
        if #node < 2 then return false end
        for i = 2, #node do
            if not validate_node(node[i], rid, depth + 1, inside_not) then return false end
        end
        return true
    end

    if type(node.cond) == 'string' then
        local name = node.cond
        local op = node.op or 're'
        if not INLINE_CONDS[name] then
            ngx_log(ERR, 'combo: unknown cond "', tostring(name), '" in rule "', rid, '"')
            return false
        end
        if name == 'header_count' then
            local n = tonumber(node.value)
            if not HEADER_COUNT_OPS[op] or not n or n < 0 or n == math.huge or n % 1 ~= 0 then return false end
        else
            if not INLINE_OPS[op] then
                ngx_log(ERR, 'combo: unknown op "', tostring(op), '" in rule "', rid, '"')
                return false
            end
            if (op == 're' or op == 'contains' or op == 'prefix' or op == 'eq')
                and type(node.value) ~= 'string' then return false end
        end
        if node.flags ~= nil and (op ~= 're' or type(node.flags) ~= 'string') then return false end
        if node.case_sensitive ~= nil
            and (name == 'header_count' or op ~= 're' or type(node.case_sensitive) ~= 'boolean') then return false end
        if node.icase ~= nil
            and (name == 'header_count' or (op ~= 'contains' and op ~= 'prefix' and op ~= 'eq')
                or type(node.icase) ~= 'boolean') then return false end
        if op == 're' then
            -- 加载期预编译: 正则写错不能留到运行期变成 unknown 再 fail-closed 拦截正常请求
            local flags = node.flags
            if flags == nil then flags = node.case_sensitive == true and 'jo' or 'joi' end
            local ok_re, re_from, _, re_err = pcall(re_find, '', node.value, flags)
            if not ok_re or re_err then
                ngx_log(ERR, 'combo: invalid regex "', string_sub(node.value, 1, 120),
                    '" in rule "', rid, '": ', tostring(ok_re and re_err or re_from))
                return false
            end
        end
        return true
    end
    return false
end

-- 统计规则需要的请求头读取上限, 避免 leaf 条件读不到
local function scan_header_needs(node, depth)
    if depth > 16 or type(node) ~= 'table' then return end
    if type(node.cond) == 'string' then
        if node.cond == 'header' then
            need_header_text = true
            if header_read_max < HEADER_TEXT_MIN then header_read_max = HEADER_TEXT_MIN end
        elseif node.cond == 'header_count' then
            local v = tonumber(node.value)
            if v and v + 1 > header_read_max then header_read_max = v + 1 end
        end
        return
    end
    for i = 2, #node do
        local child = node[i]
        if type(child) == 'table' then
            scan_header_needs(child, depth + 1)
        end
    end
end

local function compile_rule(obj)
    if type(obj) ~= 'table' then return nil end
    if type(obj.id) ~= 'string' or obj.id == '' then return nil end
    if obj.enabled == false then return nil end
    if obj['if'] == nil then return nil end

    local action = obj.action
    if action == nil then
        action = 'BLOCK'
    elseif type(action) ~= 'string' then
        ngx_log(ERR, 'combo: action must be a string in rule "', obj.id, '"')
        return nil
    end
    action = string.upper(action)
    if not ACTIONS[action] then
        ngx_log(ERR, 'combo: unknown action "', tostring(obj.action), '" in rule "', obj.id, '"')
        return nil
    end

    if not validate_node(obj['if'], obj.id, 0, false) then
        ngx_log(ERR, 'combo: invalid expression in rule "', obj.id, '"')
        return nil
    end

    local score = obj.score == nil and 10 or tonumber(obj.score)
    if not score or score ~= score or score == math.huge then
        ngx_log(ERR, 'combo: invalid score in rule "', obj.id, '"')
        return nil
    end
    if action == 'SCORE' and score <= 0 then
        ngx_log(ERR, 'combo: score must be positive in rule "', obj.id, '"')
        return nil
    end

    return {
        id = obj.id,
        action = action,
        score = score,
        cond = obj['if'],
        enabled = true,
    }
end

local function load_rules()
    if type(get_rule_entry) ~= 'function' then return nil end

    local entry = get_rule_entry(RULE_FILE)
    if not entry or not entry.rules then
        compiled_rules, compiled_sig = nil, nil
        return nil
    end

    local sig = entry.cache_key or entry.mtime
    if compiled_rules and sig == compiled_sig then
        return compiled_rules
    end

    header_read_max = HEADER_TEXT_MIN
    need_header_text = false

    local out = {}
    for i, line in ipairs(entry.rules) do
        local ok, obj = pcall(cjson.decode, line)
        if ok and type(obj) == 'table' then
            local r = compile_rule(obj)
            if r then
                scan_header_needs(r.cond, 0)
                out[#out + 1] = r
            end
        else
            ngx_log(ERR, 'combo: bad JSON at line ', i, ': ', string_sub(line, 1, 120))
        end
    end
    if header_read_max > HEADER_READ_MAX_CAP then
        header_read_max = HEADER_READ_MAX_CAP
    end

    compiled_rules, compiled_sig = out, sig
    return out
end

local function smoke_cond(c)
    local name = c.cond
    local op = c.op or 're'
    local value = c.value

    if name == 'header_count' then
        local info = get_header_info()
        if not info.valid then return nil end
        local v = tonumber(value)
        if op == 'gte' then
            if info.count >= v then return true end
            if info.complete then return false end
            return nil
        elseif op == 'lte' then
            if info.count > v then return false end
            if info.complete then return true end
            return nil
        end
        if info.complete then return info.count == v end
        if info.count > v then return false end
        return nil
    end

    local subject
    local complete = true
    local available = true
    if name == 'uri' then
        subject = var.uri
    elseif name == 'method' then
        subject = req_get_method()
    elseif name == 'protocol' then
        subject = var.server_protocol
    elseif name == 'args' then
        subject = var.args
    elseif name == 'cookie' then
        subject = var.http_cookie
    elseif name == 'header' then
        local info = get_header_info()
        subject = info.text
        complete = info.complete
        available = info.valid
    elseif name == 'body' then
        subject, complete = get_body()
    elseif name == 'ip' then
        subject = get_client_ip()
    elseif name == 'content_type' then
        subject = var.content_type
    elseif name == 'content_length' then
        subject = var.http_content_length
    elseif name == 'transfer_encoding' then
        subject = var.http_transfer_encoding
    else
        ngx_log(ERR, 'combo: unknown cond "', tostring(name), '"')
        return false
    end

    if not available then return nil end

    if op == 'exists' then
        if subject ~= nil then return true end
        if not complete then return nil end
        return false
    end
    if subject == nil then
        if not complete then return nil end
        return false
    end

    if op == 're' then
        -- Regex anchors can refer to the end of the supplied string. A match
        -- against a truncated prefix is therefore not necessarily a match
        -- against the complete request field.
        if not complete then return nil end
        -- 默认忽略大小写 (joi); flags 显式覆盖, 或 case_sensitive:true 关闭
        local flags = c.flags
        if flags == nil then flags = c.case_sensitive == true and 'jo' or 'joi' end
        local ok, from, _, err = pcall(re_find, subject, value, flags)
        if not ok or err then
            ngx_log(ERR, 'combo: regex evaluation failed: ', tostring(ok and err or from))
            return nil
        end
        return from ~= nil
    elseif op == 'eq' then
        if not complete then return nil end
        -- method/protocol 是大小写敏感的字面量, 默认精确比较; 其他字段默认忽略大小写
        local icase = c.icase
        if icase == nil then icase = name ~= 'method' and name ~= 'protocol' end
        if icase then return string_lower(subject) == string_lower(value) end
        return subject == value
    elseif op == 'contains' then
        -- 默认忽略大小写; icase:false 关闭
        local icase = c.icase
        if icase == nil then icase = true end
        local matched
        if icase then
            matched = string_find(string_lower(subject), string_lower(value), 1, true) ~= nil
        else
            matched = string_find(subject, value, 1, true) ~= nil
        end
        if matched then return true end
        if not complete then return nil end
        return false
    elseif op == 'prefix' then
        if not complete and #value > #subject then return nil end
        -- 默认忽略大小写; icase:false 关闭
        if c.icase == false then
            return string_sub(subject, 1, #value) == value
        end
        return string_lower(string_sub(subject, 1, #value)) == string_lower(value)
    end
    return nil
end

local eval_node

eval_node = function(node)
    local t = type(node)
    if t == 'string' then
        return _M.detect_state(node)
    end
    if t ~= 'table' then return false end

    local op = node[1]
    if op == 'AND' then
        local unknown = false
        for i = 2, #node do
            local result = eval_node(node[i])
            if result == false then return false end
            if result == nil then unknown = true end
        end
        if unknown then return nil end
        return true
    elseif op == 'OR' then
        local unknown = false
        for i = 2, #node do
            local result = eval_node(node[i])
            if result == true then return true end
            if result == nil then unknown = true end
        end
        if unknown then return nil end
        return false
    elseif op == 'NOT' then
        local result = eval_node(node[2])
        if result == nil then return nil end
        return not result
    elseif op == 'AT_LEAST' then
        local need = tonumber(node[2])
        local matched, unknown = 0, 0
        for i = 3, #node do
            local result = eval_node(node[i])
            if result == true then
                matched = matched + 1
                if matched >= need then return true end
            elseif result == nil then
                unknown = unknown + 1
            end
        end
        if matched + unknown >= need then return nil end
        return false
    end
    if type(node.cond) == 'string' then
        return smoke_cond(node)
    end
    return false
end

--=========================================================================
-- L3: 动作执行
--=========================================================================
local function waf_on()
    return get_effective_config('waf_enable') == 'on'
end

local function log_action(method, rule, detail)
    log_record(method, var.request_uri, detail or '-', rule.id)
end

local function do_action(rule)
    local action = rule.action

    if action == 'LOG' then
        log_action('Combo_LOG', rule)
        return false
    end

    if action == 'ALERT' then
        log_action('Combo_ALERT', rule)
        return false
    end

    if action == 'SCORE' then
        local total = (ngx.ctx._waf_score or 0) + rule.score
        ngx.ctx._waf_score = total
        log_action('Combo_SCORE', rule, 'score:' .. tostring(rule.score) .. ' total:' .. tostring(total))
        local threshold = tonumber(get_effective_config('score_block_threshold')) or 0
        if threshold > 0 and total >= threshold then
            log_action('Combo_SCORE_BLOCK', rule, 'total:' .. tostring(total))
            if waf_on() then
                waf_output()
                return true
            end
        end
        return false
    end

    if action == 'CHALLENGE' then
        -- 复用统一输出配置 (config_waf_output / config_waf_redirect_url):
        -- html 模式返回 403 页面, redirect 模式跳转; 与 BLOCK 输出一致, 仅日志标签不同
        log_action('Combo_CHALLENGE', rule)
        if not waf_on() then return false end
        waf_output()
        return true
    end

    -- BLOCK
    log_action('Combo_BLOCK', rule)
    if waf_on() then
        waf_output()
        return true
    end
    return false
end

local function do_indeterminate(rule)
    log_action('Combo_INDETERMINATE', rule, 'expression could not be fully evaluated')
    if (rule.action == 'BLOCK' or rule.action == 'CHALLENGE') and waf_on() then
        waf_output()
        return true
    end
    return false
end

-- 评估 combo.jsonl; 返回 true 表示请求已被终止 (BLOCK/CHALLENGE/SCORE 达阈值)
function _M.run()
    local rules = load_rules()
    if not rules or #rules == 0 then return false end

    for i = 1, #rules do
        local rule = rules[i]
        local ok, hit = pcall(eval_node, rule.cond)
        if not ok then
            ngx_log(ERR, 'combo: eval failed in rule "', rule.id, '": ', tostring(hit))
            if do_indeterminate(rule) then return true end
        elseif hit == nil then
            if do_indeterminate(rule) then return true end
        elseif hit then
            if do_action(rule) then return true end
        end
    end
    return false
end

return _M
