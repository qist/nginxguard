# waf
## nginx waf 

基于 Lua 的 Nginx WAF（Web Application Firewall），支持 **基于域名的规则配置**。

### 安装依赖
```sh
# 安装依赖
 yum install -y lua-devel 
 git clone https://github.com/openresty/luajit2.git
 cd luajit2
 make -j$(nproc) && make -j$(nproc) install
 ln -sf /usr/local/lib/libluajit-5.1.so.2 /lib64/libluajit-5.1.so.2
 cd ../
 wget https://www.kyne.com.au/~mark/software/download/lua-cjson-2.1.0.tar.gz
 tar -xzvf lua-cjson-2.1.0.tar.gz
 cd lua-cjson-2.1.0
 make -j$(nproc) && make -j$(nproc) install
 cd ../
 git clone https://github.com/diegonehab/luasocket.git
 cd luasocket
 make -j$(nproc) && make -j$(nproc) install
 export LUAJIT_LIB=/usr/local/lib
 export LUAJIT_INC=/usr/local/include/luajit-2.1
 cd ../
 git clone https://github.com/simplresty/ngx_devel_kit.git
 git clone --branch v0.10.14 https://github.com/openresty/lua-nginx-module.git
  # 下载nginx
  wget https://nginx.org/download/nginx-1.15.10.tar.gz
  tar -xvf nginx-1.15.10.tar.gz
  cd nginx-1.15.10
  ./configure --add-module=../lua-nginx-module \
             --add-module=../ngx_devel_kit 
```

### 文件结构
```
waf/
├── config.lua              # 全局配置（开关、日志路径、规则目录等）
├── init.lua                # init_by_lua_file 预加载模块
├── access.lua              # access_by_lua_file 每请求 WAF 检测入口
├── lib.lua                 # WAF 核心库（IP获取、规则加载、域名配置、日志、输出）
├── nginx-config/
│   └── nginx.conf          # nginx 配置示例
└── rule-config/
    ├── domain.json         # 域名级规则配置（仅放需要覆盖全局的域名）
    ├── args.rule           # 全局 URL 参数规则
    ├── blackip.rule        # 全局黑名单 IP
    ├── cookie.rule         # 全局 Cookie 规则
    ├── post.rule           # 全局 POST 规则
    ├── url.rule            # 全局 URL 规则
    ├── useragent.rule      # 全局 User-Agent 规则
    ├── whiteip.rule        # 全局白名单 IP
    ├── whiteurl.rule       # 全局白名单 URL
    ├── whiteua.rule        # 全局白名单 UA（搜索引擎爬虫）
    ├── referer.rule        # 全局 Referer 规则
    ├── fileext.rule        # 全局文件上传扩展名规则
    └── domains/                # 域名专属规则目录
        └── www.example.com/
            ├── args.rule          # URL参数攻击规则
            ├── blackip.rule       # 黑名单IP（空文件=无黑名单）
            ├── cookie.rule        # Cookie攻击规则
            ├── post.rule          # POST攻击规则
            ├── url.rule           # URL路径攻击规则
            ├── useragent.rule     # User-Agent攻击规则
            ├── whiteip.rule       # 白名单IP（空文件=无白名单）
            ├── whiteurl.rule      # URL白名单
            ├── whiteua.rule       # UA白名单（搜索引擎爬虫放行）
            ├── referer.rule       # Referer攻击规则
            └── fileext.rule       # 文件上传扩展名规则
```

---

## 基于域名的规则配置

### 配置优先级

```
域名级配置 (domain.json 中对应域名的配置)    ← 最高优先级
    ↓ 该域名未配置或某字段未设置时回退
全局配置 (config.lua 中的 config_* 变量)      ← 全局基线
```

- **`config.lua` 是全局基线**：所有未在 `domain.json` 中配置的域名，都走 `config.lua` 的全局配置
- **`domain.json` 只放需要覆盖的域名**：只有需要差异化配置的域名才写进来
- **域名中未指定的字段自动回退到全局**：比如域名只配了 `url_check`，其他检测项仍走全局

### domain.json 配置格式

```json
{
    "_comment": "只配置需要覆盖全局(config.lua)的域名",

    "www.example.com": {
        "url_check": "off",
        "cc_rate": "100/60",
        "cc_block_ttl": 300,
        "rule_dir": "domains/www.example.com"
    },

    "api.example.com": {
        "waf_enable": "off"
    },

    "*.test.com": {
        "post_check": "off",
        "cookie_check": "off"
    }
}
```

### 配置项说明

| 字段 | 说明 | 对应 config.lua 变量 |
|------|------|---------------------|
| `waf_enable` | WAF 总开关 | `config_waf_enable` |
| `trust_proxy_headers` | 是否信任代理转发的 IP 头（X-Forwarded-For 等）。`"on"`=WAF 在 CDN/反代后，信任转发头；`"off"`=WAF 直接暴露，只用 `remote_addr` 防伪造 | `config_trust_proxy_headers` |
| `white_url_check` | 白名单 URL 检测 | `config_white_url_check` |
| `white_ua_check` | 白名单 UA 检测（搜索引擎爬虫放行，仅跳过 UA 黑名单检测，不影响 URL/POST/CC 等其他检测） | `config_white_ua_check` |
| `white_ip_check` | 白名单 IP 检测 | `config_white_ip_check` |
| `black_ip_check` | 黑名单 IP 检测 | `config_black_ip_check` |
| `url_check` | URL 攻击检测 | `config_url_check` |
| `url_args_check` | URL 参数检测 | `config_url_args_check` |
| `user_agent_check` | User-Agent 检测 | `config_user_agent_check` |
| `cookie_check` | Cookie 检测 | `config_cookie_check` |
| `cc_check` | CC 攻击检测 | `config_cc_check` |
| `cc_rate` | CC 限速（次数/秒数） | `config_cc_rate` |
| `cc_block_ttl` | CC 触发后自动拉黑 IP 的时长（秒），0=不自动拉黑，默认 600（10分钟） | `config_cc_block_ttl` |
| `post_check` | POST 检测（表单 + JSON body） | `config_post_check` |
| `referer_check` | Referer 检测 | `config_referer_check` |
| `file_upload_check` | 文件上传扩展名检测 | `config_file_upload_check` |
| `waf_output` | 拦截输出方式 | `config_waf_output` |
| `waf_redirect_url` | 跳转 URL | `config_waf_redirect_url` |
| `rule_dir` | 域名专属规则目录路径，支持绝对路径或相对路径 | （无全局对应，默认走 `config_rule_dir`） |

### 通配符域名

支持通配符域名匹配，格式为 `*.example.com`，会匹配所有子域名如 `a.test.com`、`b.test.com` 等。

匹配规则：**精确域名优先 > 通配符匹配 > 全局 config.lua**。

### 域名专属规则目录

在域名配置中设置 `rule_dir` 后，WAF 加载规则文件时会优先从该目录读取。所有规则文件都支持域名独立配置：

| 规则文件 | 检测函数 | 说明 |
|---------|---------|------|
| `whiteip.rule` | `white_ip_check()` | IP 白名单 |
| `blackip.rule` | `black_ip_check()` | IP 黑名单 |
| `whiteurl.rule` | `white_url_check()` | URL 白名单 |
| `whiteua.rule` | `user_agent_attack_check()` 内部调用 `is_white_ua()` | UA 白名单（搜索引擎爬虫放行，仅跳过 UA 黑名单检测） |
| `url.rule` | `url_attack_check()` | URL 路径攻击检测 |
| `args.rule` | `url_args_attack_check()` | URL 参数攻击检测 |
| `useragent.rule` | `user_agent_attack_check()` | User-Agent 攻击检测 |
| `cookie.rule` | `cookie_attack_check()` | Cookie 攻击检测 |
| `post.rule` | `post_attack_check()` | POST 攻击检测（表单 + JSON body） |
| `referer.rule` | `referer_check()` | Referer 检测 |
| `fileext.rule` | `file_upload_check()` | 文件上传扩展名检测 |

`rule_dir` 支持两种写法：
- **绝对路径**：以 `/` 开头，如 `/apps/nginx/conf/waf/rule-config/domains/www.example.com`
- **相对路径**：不以 `/` 开头，相对于全局 `config_rule_dir` 解析，如 `domains/www.example.com` 实际解析为 `config_rule_dir/domains/www.example.com`

#### 规则文件回退机制

WAF 加载规则时，会先在域名 `rule_dir` 目录中查找，找不到再回退到全局 `rule-config/` 目录。**关键区别在于文件是否存在**：

| 域名目录中 | 行为 | 说明 |
|:---------:|------|------|
| 文件不存在 | 回退全局 | 使用 `rule-config/` 下的同名规则文件 |
| 空文件 | 不回退 | 返回空规则表，等同于该域名单项无规则 |
| 有内容的文件 | 使用域名规则 | 只用域名目录中的规则，不合并全局 |

例如 `www.example.com` 配置了 `rule_dir`，域名目录下有 `url.rule` 和 `whiteurl.rule`，但没放 `args.rule`：
- `url.rule` → 有文件，使用域名专属规则
- `whiteurl.rule` → 有文件，使用域名专属规则
- `args.rule` → 文件不存在，回退到全局 `rule-config/args.rule`
- `whiteip.rule` → 空文件，不回退，该域名无白名单 IP
- `blackip.rule` → 空文件，不回退，该域名无黑名单 IP

> **提示**：如果希望某项规则回退全局，不要在域名目录放该文件（包括空文件）。空文件等于明确指定

### 使用示例

**场景 1：为 API 域名关闭 WAF**
```json
"api.example.com": {
    "waf_enable": "off"
}
```

**场景 2：为某个域名单独放宽 CC 限制，其他配置走全局**
```json
"www.example.com": {
    "cc_rate": "200/60"
}
```

**场景 3：为某个域名关闭 URL 检测并使用独立规则目录**
```json
"www.example.com": {
    "url_check": "off",
    "rule_dir": "domains/www.example.com"
}
```
然后在 `domains/www.example.com/` 目录下放置 `url.rule`、`whiteurl.rule` 等规则文件。

**场景 4：为所有子域名关闭 POST 和 Cookie 检测**
```json
"*.test.com": {
    "post_check": "off",
    "cookie_check": "off"
}
```

**场景 5：CC 触发后自动拉黑 IP，10 分钟后自动解封**
```json
"www.example.com": {
    "cc_rate": "60/60",
    "cc_block_ttl": 600
}
```
CC 超限后 IP 自动加入 `badGuys` 共享字典，600 秒内所有请求直接 403，600 秒后自动解封。设为 `0` 则关闭自动拉黑，只拦截当前请求。

**场景 6：WAF 直接暴露公网，防止 IP 伪造**
```lua
-- config.lua
config_trust_proxy_headers = "off"
```
当 WAF 不在 CDN/反向代理后面时，设置为 `"off"` 可防止攻击者伪造 `X-Forwarded-For` 头绕过 IP 黑白名单和 CC 限制。此时 WAF 只使用 TCP 连接的真实远端 IP（`remote_addr`）。支持域名级覆盖：

```json
{
    "www.example.com": {
        "trust_proxy_headers": "on"
    },
    "direct.example.com": {
        "trust_proxy_headers": "off"
    }
}
```
上面的例子中，`www.example.com` 走 CDN 信任转发头，而 `direct.example.com` 直连暴露只认 `remote_addr`，互不影响。

### 不使用域名配置

如果 `rule-config/domain.json` 文件不存在或格式错误，WAF 会自动回退到 `config.lua` 中的全局配置，行为与旧版完全一致。

---

## 规则缓存与热加载

### 缓存机制

WAF 使用 `ngx.shared.dict` 缓存规则文件和域名配置，避免每次请求都读磁盘。缓存失效策略基于**文件修改时间（mtime）**：

- **LuaJIT FFI `stat()`**（首选）：通过 FFI 直接调用 libc 的 `stat()` 系统函数获取文件 mtime，**无需编译任何 C 模块**，纯 Lua 实现。支持现代 glibc（`stat()`）和旧版 glibc（`__xstat()`），兼容 x86_64 和 aarch64。
- **文件大小回退**（降级）：当 FFI 不可用时，回退为使用文件大小 + 60 秒 TTL 作为缓存失效判断。可靠性略低于 mtime，但功能正常。

修改规则文件后**无需 reload nginx**，下次请求自动检测到 mtime 变化并重新加载规则。

### 白名单 UA 安全说明

`whiteua.rule` 中的搜索引擎爬虫（Googlebot、Baiduspider 等）**仅跳过 UA 黑名单检测**（`useragent.rule`），不会跳过其他任何安全检测：

| 检测项 | 白名单 UA 是否跳过 |
|--------|:----------------:|
| User-Agent 黑名单 (`useragent.rule`) | ✅ 跳过 |
| URL 攻击检测 (`url.rule`) | ❌ 仍检测 |
| URL 参数检测 (`args.rule`) | ❌ 仍检测 |
| POST 攻击检测 (`post.rule`) | ❌ 仍检测 |
| CC 攻击检测 | ❌ 仍检测 |
| Cookie 检测 (`cookie.rule`) | ❌ 仍检测 |
| 文件上传检测 (`fileext.rule`) | ❌ 仍检测 |
| IP 黑白名单 | ❌ 仍检测 |

这样设计可以防止攻击者伪造搜索引擎 UA 来绕过 WAF 的其他安全检测。

### 日志

WAF 日志中新增了 `domain` 字段，记录触发规则的请求域名，便于按域名分析攻击日志。

| attack_method | 说明 |
|---------------|------|
| `BlackList_IP` | 静态黑名单 IP 拦截（blackip.rule） |
| `Dynamic_Block_IP` | 动态黑名单拦截（CC 自动拉黑，封禁期内） |
| `CC_Attack` | CC 限速触发 |
| `CC_AutoBan` | CC 触发后 IP 被自动拉黑，记录封禁时长 |
| `Deny_URL` | URL 攻击拦截 |
| `Deny_URL_Args` | URL 参数攻击拦截 |
| `Deny_URL_POST` | POST 攻击拦截 |
| `Deny_USER_AGENT` | User-Agent 攻击拦截 |
| `Deny_Cookie` | Cookie 攻击拦截 |
| `Deny_Referer` | Referer 拦截 |
| `Deny_File_Upload` | 文件上传拦截 |

---

## 性能测试

### 测试环境

| 项目 | 配置 |
|------|------|
| CPU | 4 核 x86_64 |
| 内存 | 24 GB |
| OS | Linux |
| Nginx | 1.31.3 + LuaJIT |
| 并发 | 100 并发，20000 请求，Keep-Alive |
| 测试工具 | ApacheBench (ab) |
| 测试方法 | 每场景 3 次取最佳值，避免系统波动干扰 |

### 优化措施

| 优化项 | 说明 |
|--------|------|
| 合并正则 | N 条规则合并为 `(?:rule1\|rule2\|...)`，正常流量匹配从 O(N) 降至 O(1) |
| TTL 缓存 | 10s 缓存窗口消除每请求 ~10 次 `stat()` 系统调用 |
| FFI stat | LuaJIT FFI 直接调用 libc `stat()` 获取 mtime，避免 Lua IO 开销 |
| glob 预编译 | IP 通配符规则（`192.168.*`）在加载时预编译 regex |
| cc_rate 缓存 | CC 限速参数解析提升到 worker 级，仅配置变更时重解析 |
| waf_enable 缓存 | 每请求 ~13 次 `get_effective_config` 改为 `ngx.ctx` 首次缓存 |
| require 模块级 | `cjson`/`io`/`os` 从函数内 `require` 提到模块顶部 |
| 消除冗余调用 | `file_upload_check`/`post_attack_check` 移除多余的 `get_rule` 调用 |

### 测试结果

| 场景 | req/s | CPU | RSS | P99 | 吞吐下降 |
|------|-------|-----|-----|-----|---------|
| WAF 全关（基线） | 34,180 | 256% | 69 MB | 10.2ms | — |
| WAF 全开（无 CC/POST） | 34,128 | 233% | 70 MB | 13.3ms | 0.2% |
| WAF + CC | 34,202 | 169% | 70 MB | 9.1ms | — |
| WAF + POST | 33,741 | 256% | 69 MB | 15.0ms | 1.3% |
| WAF 全开（生产） | 34,692 | 275% | 69 MB | 12.8ms | — |

> **结论**：经过合并正则、TTL 缓存、FFI stat、glob 预编译等深度优化后，WAF 全开相比 WAF 全关的吞吐下降 **< 2%**，P99 延迟增加约 2-3ms，内存增加约 1MB。在正常流量场景下，WAF 的性能开销几乎可以忽略不计。
