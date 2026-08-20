# NginxGuard
## NginxGuard

基于 Lua 的 NginxGuard（Web Application Firewall），支持 **基于域名的规则配置**、**IPv6 黑白名单**、**云凭据探测拦截** 等。

### 安装依赖

```sh
# 1. 安装编译依赖
yum install -y gcc make git wget \
    pcre-devel zlib-devel openssl-devel \
    libxml2-devel libxslt-devel gd-devel

# 2. 编译安装 LuaJIT2 (OpenResty 分支)
git clone https://github.com/openresty/luajit2.git
cd luajit2
make -j$(nproc) && make install
ln -sf /usr/local/lib/libluajit-5.1.so.2 /lib64/libluajit-5.1.so.2
cd ../

# 3. 编译安装 lua-cjson (OpenResty 官方 fork)
git clone https://github.com/openresty/lua-cjson.git
cd lua-cjson
# 需指定 LuaJIT 的头文件和库路径
export LUAJIT_LIB=/usr/local/lib
export LUAJIT_INC=/usr/local/include/luajit-2.1
make -j$(nproc) && make install
cd ../

# 4. 下载 lua-nginx-module (最新稳定版 v0.10.31)
git clone --branch v0.10.31 https://github.com/openresty/lua-nginx-module.git

# 5. 下载 ngx_devel_kit (lua-nginx-module 的前置依赖)
git clone https://github.com/simplresty/ngx_devel_kit.git

# 6. 下载并编译 Nginx (mainline 1.31.3, 如需 stable 可用 1.30.4)
wget https://nginx.org/download/nginx-1.31.3.tar.gz
tar -xvf nginx-1.31.3.tar.gz
cd nginx-1.31.3

export LUAJIT_LIB=/usr/local/lib
export LUAJIT_INC=/usr/local/include/luajit-2.1

./configure \
    --add-module=../ngx_devel_kit \
    --add-module=../lua-nginx-module \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-http_realip_module \
    --with-http_stub_status_module \
    --with-http_gzip_static_module \
    --with-http_gunzip_module \
    --with-threads \
    --with-file-aio
make -j$(nproc) && make install
```

> 完整的静态编译方案（含全部第三方模块和 Lua 生态静态编入）见 [nginx-binaries](https://github.com/qist/nginx-binaries)。

### 文件结构
```
waf/
├── config.lua              # 全局配置（开关、日志路径、规则目录等）
├── init.lua                # init_by_lua_file 预加载模块
├── access.lua              # access_by_lua_file 每请求 NginxGuard 检测入口
├── lib.lua                 # NginxGuard 核心库（IP获取、规则加载、域名配置、日志、输出）
├── nginx-config/
│   └── nginx.conf          # nginx 配置示例
└── rule-config/
    ├── domain.json         # 域名级规则配置（仅放需要覆盖全局的域名）
    ├── args.rule           # 全局 URL 参数规则
    ├── blackip.rule        # 全局黑名单 IP（支持 IPv4/IPv6 CIDR/通配符/精确IP）
    ├── cdnip.rule          # CDN/可信代理 IP 列表（控制 XFF 信任，支持 CIDR）
    ├── cookie.rule         # 全局 Cookie 规则
    ├── post.rule           # 全局 POST 规则
    ├── url.rule            # 全局 URL 规则
    ├── useragent.rule      # 全局 User-Agent 规则
    ├── whiteip.rule        # 全局白名单 IP（支持 IPv4/IPv6 CIDR/通配符/精确IP）
    ├── whiteurl.rule       # 全局白名单 URL
    ├── whiteua.rule        # 全局白名单 UA（搜索引擎爬虫）
    ├── referer.rule        # 全局 Referer 规则
    ├── fileext.rule        # 全局文件上传扩展名规则
    └── domains/                # 域名专属规则目录
        └── www.example.com/
            ├── args.rule          # URL参数攻击规则
            ├── blackip.rule       # 黑名单IP（支持 IPv4/IPv6 CIDR/通配符/精确IP，空文件=无黑名单）
            ├── cookie.rule        # Cookie攻击规则
            ├── post.rule          # POST攻击规则
            ├── url.rule           # URL路径攻击规则
            ├── useragent.rule     # User-Agent攻击规则
            ├── whiteip.rule       # 白名单IP（支持 IPv4/IPv6 CIDR/通配符/精确IP，空文件=无白名单）
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
| `waf_enable` | NginxGuard 总开关 | `config_waf_enable` |
| `trust_proxy_headers` | 是否信任代理转发的 IP 头（X-Forwarded-For 等）。`"on"`=NginxGuard 在 CDN/反代后，根据 `cdnip.rule` 判断是否信任转发头：`remote_addr` 在 `cdnip.rule` 中才信任 XFF，不在则用 `remote_addr` 防伪造；`cdnip.rule` 不存在或为空则信任所有 XFF（原始方案，存在伪造风险）。`"off"`=NginxGuard 直接暴露公网，只用 `remote_addr` 防伪造 | `config_trust_proxy_headers` |
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

在域名配置中设置 `rule_dir` 后，NginxGuard 加载规则文件时会优先从该目录读取。所有规则文件都支持域名独立配置：

| 规则文件 | 检测函数 | 说明 |
|---------|---------|------|
| `whiteip.rule` | `white_ip_check()` | IP 白名单（支持 IPv4/IPv6/通配符） |
| `blackip.rule` | `black_ip_check()` | IP 黑名单（支持 IPv4/IPv6/通配符） |
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

NginxGuard 加载规则时，会先在域名 `rule_dir` 目录中查找，找不到再回退到全局 `rule-config/` 目录。**关键区别在于文件是否存在**：

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

> **提示**：如果希望某项规则回退全局，不要在域名目录放该文件（包括空文件）。空文件等于明确指定"无规则"

### 使用示例

**场景 1：为 API 域名关闭 NginxGuard**
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

**场景 6：NginxGuard 在 CDN 后面，仅信任 CDN IP 的 XFF**

当 NginxGuard 部署在 CDN/反向代理后面时，需要从 `X-Forwarded-For` 获取真实客户端 IP。但直接信任 XFF 会让攻击者伪造该头绕过 IP 黑白名单。

解决方案：在 `config.lua` 中设置 `trust_proxy_headers = "on"`，并在 `rule-config/cdnip.rule` 中配置你实际使用的 CDN/代理 IP 段：

```lua
-- config.lua
config_trust_proxy_headers = "on"
```

```bash
# rule-config/cdnip.rule
# 填入你实际使用的 CDN/代理 IP 段，以下为示例（请按需替换）
# 各家 CDN IP 列表查询地址：
#   Cloudflare:    https://www.cloudflare.com/ips/
#   AWS CloudFront: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/LocationsOfEdgeServers.html
#   Akamai:        https://developer.akamai.com/cli/apps/akamai-cli-list-ip
#   阿里云 CDN:    https://help.aliyun.com/document_detail/27134.html
#   腾讯云 CDN:    https://cloud.tencent.com/document/product/228/52935

# Cloudflare IPv4（示例）
173.245.48.0/20
104.16.0.0/13
# Cloudflare IPv6（示例）
2400:cb00::/32
2606:4700::/32
# 内部代理/负载均衡器
10.0.0.0/8
192.168.0.0/16
```

此时 NginxGuard 的行为：

| 条件 | XFF 处理 | 说明 |
|------|---------|------|
| `remote_addr` 在 cdnip.rule 中 | 信任 XFF | 提取真实客户端 IP |
| `remote_addr` 不在 cdnip.rule 中 | 不信任 XFF | 使用 `remote_addr`（防直连伪造） |
| `cdnip.rule` 文件不存在 | 信任所有 XFF | 原始行为，向后兼容 |
| `cdnip.rule` 文件为空（或全注释） | 信任所有 XFF | 等同于文件不存在，回落原始行为 |

支持域名级覆盖：

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

**场景 7：NginxGuard 直接暴露公网，防止 IP 伪造**
```lua
-- config.lua
config_trust_proxy_headers = "off"
```
当 NginxGuard 不在 CDN/反向代理后面时，设置为 `"off"` 可防止攻击者伪造 `X-Forwarded-For` 头绕过 IP 黑白名单和 CC 限制。此时 NginxGuard 只使用 TCP 连接的真实远端 IP（`remote_addr`）。

### 不使用域名配置

如果 `rule-config/domain.json` 文件不存在或格式错误，NginxGuard 会自动回退到 `config.lua` 中的全局配置，行为与旧版完全一致。

---

## Location 级别开关

除了域名级和全局级开关，NginxGuard 还支持 **Nginx `location` 级别** 的开关。只需在需要关闭 NginxGuard 的 `location` 中加一行：

```nginx
location /234567 {
    set $waf_enable off;          # ← 关闭 NginxGuard，就这一行

    grpc_pass grpc://234567;
}
```

### 工作原理

NginxGuard 在 `http` 块全局挂载（`access_by_lua_file`），每个请求进入时首先检查 Nginx 变量 `$waf_enable`：

```lua
if ngx.var.waf_enable == "off" then
    return          -- 直接跳过所有 NginxGuard 检测
end
```

- **未设置 `$waf_enable`**（绝大多数 location）：变量为 `nil`，不等于 `"off"`，NginxGuard 正常执行
- **`set $waf_enable off;`**：该 location 下 NginxGuard 完全跳过，不影响其他 location

### 优先级

```
location 级 (set $waf_enable off;)    ← 最高优先级
    ↓
域名级 (domain.json 中 waf_enable)    ← 次之
    ↓
全局级 (config.lua 中 config_waf_enable)  ← 基线
```

> `location` 级开关会跳过**所有** NginxGuard 检测（IP 黑白名单、CC、URL、POST 等），适用于 gRPC、WebSocket 等非 HTTP 标准请求路径。

### 典型场景

**gRPC 长连接关闭 NginxGuard**：

```nginx
location /23456 {
    set $waf_enable off;
    client_max_body_size 0;
    keepalive_requests 4294967296;
    client_body_timeout 1h;
    send_timeout 1h;
    lingering_close always;
    grpc_set_header X-Real-IP $clientRealIp;
    grpc_read_timeout 1h;
    grpc_send_timeout 1h;
    grpc_pass grpc://23456;
}
```

**WebSocket 升级路径关闭 NginxGuard**：

```nginx
location /ws {
    set $waf_enable off;
    proxy_pass http://backend;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}
```

---

## IP 规则与 CIDR 支持

NginxGuard 的 IP 规则文件（`blackip.rule` / `whiteip.rule` / `cdnip.rule`）全面支持 IPv4、IPv6、CIDR、通配符和精确 IP 匹配。所有 IP 规则文件使用统一的预编译引擎，支持 `#` 注释行。

### 支持的 IP 格式

| 格式 | 示例 | 说明 |
|------|------|------|
| IPv4 CIDR | `192.168.0.0/16` | 匹配 192.168.0.0 ~ 192.168.255.255（二分查找 O(log n)） |
| IPv6 CIDR | `2001:db8::/32` | 匹配 2001:db8:0000:0000:... ~ 2001:db8:ffff:... |
| IPv4 精确 | `192.168.1.100` | 完全匹配单个 IPv4 地址 |
| IPv6 精确 | `2001:db8::1` | 完全匹配单个 IPv6 地址（大小写不敏感） |
| IPv4 通配符 | `192.168.*` | 匹配 `192.168.` 开头的所有 IPv4（`*` → `\d+`） |
| IPv4 段通配 | `192.168.0.*` | 匹配 `192.168.0.0` ~ `192.168.0.255` |
| IPv6 通配符 | `2001:db8::*` | 匹配 `2001:db8::` 开头的所有 IPv6（`*` → `[\da-fA-F:]+`） |
| 注释行 | `# Cloudflare IPs` | `#` 开头的行自动跳过 |

### glob_to_regex 转换逻辑

IPv4 和 IPv6 通配符使用不同的替换策略，防止跨格式误匹配：

```
IPv4: 192.168.0.*
  转义: 192\.168\.0\.*
  替换: 192\.168\.0\.[\d]+        ← 仅匹配数字，不会误匹配 IPv6
  锚定: ^192\.168\.0\.[\d]+$

IPv6: 2001:db8::*
  转义: 2001\:db8\::*
  替换: 2001\:db8\::[\da-fA-F:]+  ← 匹配十六进制+冒号
  锚定: ^2001\:db8\::[\da-fA-F:]+$
```

### CIDR 预编译性能

CIDR 规则在文件加载时预编译为数值区间，查找性能极高：

| 规模 | 匹配方式 | 查找复杂度 |
|------|---------|------------|
| 1195 条 IPv4 CIDR | 排序数组 + 二分查找 | O(log n) ≈ 11 次比较 |
| IPv6 CIDR | 4×32-bit chunk mask 匹配 | O(n)，通常 <20 条 |
| 通配符 | 预编译 regex | O(n)，通常 <10 条 |
| 精确 IP | 小写化字符串比较 | O(n)，通常 <100 条 |

### IP 规则文件示例

```bash
# blackip.rule — 支持 CIDR、通配符、精确IP、注释
8.8.8.8                    # 精确 IP
10.0.0.0/8                 # IPv4 CIDR
192.168.0.0/16             # IPv4 CIDR
2001:db8::/32              # IPv6 CIDR
fe80::*                    # IPv6 通配符
::1                        # IPv6 精确
# 这是注释行，自动跳过
```

### Nginx 监听 IPv6

NginxGuard 支持 IPv6 流量，需确保 Nginx 同时监听 IPv6 端口：

```nginx
server {
    listen 80;
    listen [::]:80;       # 监听 IPv6
    server_name www.example.com;
    # ...
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;  # 监听 IPv6 HTTPS
    server_name www.example.com;
    # ...
}
```

当 `trust_proxy_headers = "on"` 时，NginxGuard 从 `X-Forwarded-For` / `X-Real-IP` / `CF-Connecting-IP` 中提取客户端 IP，自动兼容 IPv6 格式。当 `trust_proxy_headers = "off"` 时，直接使用 `ngx.var.remote_addr`，Nginx 会返回 IPv6 格式的客户端地址（如 `::ffff:192.168.1.1` 或纯 IPv6 地址）。

### IP 匹配流程

```
1. IPv4 CIDR: IP 转为 32 位数值，在排序区间数组中二分查找 → O(log n)
2. IPv6 CIDR: IP 转为 4x32-bit chunk，逐条与预编译 mask 比较 → O(n)
3. 通配符: 预编译 glob regex（IPv4 用 \d+，IPv6 用 [\da-fA-F:]+）→ O(n)
4. 精确 IP: 大小写不敏感字符串比较 → O(n)
5. 命中任意一条即返回 true
```

所有 IP 规则在文件加载时预编译并缓存（TTL 10s + mtime 检查），避免每请求重复解析。

---

## 云服务凭据探测拦截

`url.rule` 中新增了针对云服务凭据和敏感配置文件的探测拦截规则，覆盖常见攻击者扫描路径：

### 新增规则一览

| 规则 | 拦截目标 |
|------|----------|
| `/firebase.*\.json` | Firebase 配置文件探测 |
| `/gcp-key\.json` | GCP 服务账号密钥探测 |
| `/sa\.json` | GCP Service Account 密钥 |
| `/service[-_]account.*\.json` | 通用服务账号密钥 |
| `/google-credentials\.json` | Google 凭据文件 |
| `/aws.*key` | AWS Access Key 文件 |
| `/\.aws\/` | AWS 凭据目录 |
| `/\.gcloud\/` | GCP 凭据目录 |
| `/cloudflare.*\.json` | Cloudflare API 配置 |
| `/push_config\.json` | 推送服务配置 |
| `/gc-service\.json` | GCP 服务配置 |

### 其他敏感路径规则

`url.rule` 还包含以下探测拦截：

- **版本控制目录**：`/.git/`、`/.svn/`、`/.gitignore`、`/.dockerignore`
- **环境配置文件**：`/.env`、`/.htaccess`、`/.htpasswd`、`/config.json|yml|yaml|xml`
- **包管理文件**：`/composer.json`、`/package.json`、`/package-lock.json`、`/yarn.lock`、`/Pipfile`、`/requirements.txt`、`/Dockerfile`、`/docker-compose.yml`
- **SSH 密钥**：`/id_rsa`、`/id_dsa`、`/.ssh/`、`/authorized_keys`、`/.npmrc`
- **基础设施**：`/terraform.tfstate`、`/.idea/`、`/.vscode/`
- **管理后台**：`/wp-admin/`、`/administrator/`、`/phpmyadmin`、`/manager/html`、`/jmx-console/`
- **框架暴露**：`/actuator/*`（Spring Boot）、`/swagger-ui`、`/api-docs`、`/h2-console`、`/druid/`、`/struts2`、`/console`
- **系统敏感路径**：`/proc/self/`、`/etc/passwd`、`/etc/shadow`、`/var/log/`、`/boot.ini`、`/system32/`、`/cmd.exe`
- **Webshell 探测**：`/shell.php`、`/eval.php`、`/cmd.php`、`/upload.php`、`/connector.php`

---

## 规则缓存与热加载

### 缓存机制

NginxGuard 使用 `ngx.shared.dict` 和 **worker 级 Lua 变量** 多层缓存规则文件和域名配置，避免每次请求都读磁盘。缓存失效策略基于**文件修改时间（mtime）**：

- **LuaJIT FFI `stat()`**（首选）：通过 FFI 直接调用 libc 的 `stat()` 系统函数获取文件 mtime，**无需编译任何 C 模块**，纯 Lua 实现。支持现代 glibc（`stat()`）和旧版 glibc（`__xstat()`），兼容 x86_64 和 aarch64。
- **文件大小回退**（降级）：当 FFI 不可用时，回退为使用文件大小 + 60 秒 TTL 作为缓存失效判断。可靠性略低于 mtime，但功能正常。

修改规则文件后**无需 reload nginx**，下次请求（或 10 秒 TTL 过期后）自动检测到 mtime 变化并重新加载规则。

### 缓存层次

| 层级 | 存储位置 | 缓存内容 | 失效策略 |
|------|---------|---------|---------|
| Worker 级 | Lua 模块变量 | 规则文件内容 + 合并正则 + 预编译 glob | TTL 10s + mtime 检查 |
| Worker 级 | Lua 模块变量 | domain.json 解析结果 + 通配符后缀 | TTL 10s + mtime 检查 |
| Worker 级 | Lua 模块变量 | cc_rate 解析结果（count/seconds） | 配置变更时重解析 |
| 请求级 | `ngx.ctx` | `_client_ip`、`_domain`、`_domain_config`、`_waf_enabled` | 每请求自动清除 |

### 预编译优化

| 优化项 | 说明 |
|--------|------|
| glob 预编译 | IP 通配符规则（`192.168.*`、`2001:db8::*`）在加载时预编译为 regex，IPv4 用 `\d+`，IPv6 用 `[\da-fA-F:]+` |
| CIDR 预编译 | IPv4 CIDR 转为数值区间排序数组（二分查找）；IPv6 CIDR 转为 4×32-bit mask |
| 合并正则 | N 条规则合并为 `(?:rule1\|rule2\|...)`，正常流量匹配从 O(N) 降至 O(1) |
| 通配符后缀预编译 | `*.example.com` 预编译为 `.example.com` 后缀字符串匹配，无需正则 |

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

这样设计可以防止攻击者伪造搜索引擎 UA 来绕过 NginxGuard 的其他安全检测。

---

## 日志

### 同步写入机制

NginxGuard 日志采用**同步写入**策略，确保攻击日志在 `ngx.exit(403)` 前已落盘，不会因 Nginx 请求终止而丢失：

```lua
local file = io.open(LOG_NAME, "a")
file:write(LOG_LINE .. "\n")
file:flush()    -- 强制刷盘
file:close()
```

> 只有检测到攻击时才触发日志写入，正常流量**零日志开销**。

### 日志格式

每条日志为一行 JSON，字段如下：

| 字段 | 说明 |
|------|------|
| `@timestamp` | UTC 时间戳（ISO 8601 格式） |
| `client_ip` | 客户端 IP（IPv4 或 IPv6） |
| `local_time` | 本地时间 |
| `server_name` | 请求域名（剥离端口后的小写域名） |
| `user_agent` | 客户端 User-Agent |
| `attack_method` | 拦截类型（见下表） |
| `req_url` | 请求 URL |
| `req_data` | 请求数据/匹配到的规则 |
| `rule_tag` | 命中的具体规则内容 |

### attack_method 枚举

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

### 日志轮转

NginxGuard 内置日志轮转：当日志文件超过 **100MB** 时自动重命名为 `*.old`。轮转检查每 60 秒执行一次（非每条日志），不影响写入性能。

日志文件路径：`config_log_dir/YYYY-MM-DD_waf.log`

---

## 性能测试

### 测试环境

| 项目 | 配置 |
|------|------|
| CPU | 4 核 x86_64 |
| 内存 | 24 GB |
| OS | Linux 6.18 (RHEL 9) |
| Nginx | 1.31.3 + LuaJIT2 (OpenResty 分支) |
| 全场景压测 | 200 并发，50000 请求，Keep-Alive（GET / form POST / JSON POST 分组对比） |
| `trust_proxy_headers` 对比 | 100 并发，30000 请求，Keep-Alive |
| 测试工具 | ApacheBench (ab) + `ps`/`top` 实时采样 |
| 测试方法 | 每场景 3 次取最佳值，避免系统波动干扰 |

### 优化措施

| 优化项 | 说明 |
|--------|------|
| 合并正则 | N 条规则合并为 `(?:rule1\|rule2\|...)`，正常流量匹配从 O(N) 降至 O(1) |
| TTL 缓存 | 10s 缓存窗口消除每请求 ~10 次 `stat()` 系统调用 |
| FFI stat | LuaJIT FFI 直接调用 libc `stat()` 获取 mtime，避免 Lua IO 开销 |
| glob 预编译 | IP 通配符规则（`192.168.*`、`2001:db8::*`）在加载时预编译 regex |
| cc_rate 缓存 | CC 限速参数解析提升到 worker 级，仅配置变更时重解析 |
| 配置一次加载 | 所有 16 个配置项在请求入口一次性加载到 `ngx.ctx._cfg`，避免每检测项重复调用 `get_effective_config` |
| require 模块级 | `cjson`/`io`/`os` 从函数内 `require` 提到模块顶部 |
| 消除冗余调用 | `file_upload_check`/`post_attack_check` 移除多余的 `get_rule` 调用 |
| 同步日志 | 仅攻击触发时同步写入+flush，正常流量零 IO 开销 |
| 请求级缓存 | `client_ip`/`domain`/`domain_config`/`headers`/`is_cdn` 首次计算后缓存到 `ngx.ctx` |
| 白名单 string.find | `whiteua.rule`/`whiteurl.rule` 用 `string.find` 替代 `ngx.re.find`，避免 PCRE JIT 开销 |
| 空规则快速返回 | `match_any_rule` 检测 `entry.empty` 标志，空规则文件立即返回 nil |
| Cookie 检测后移 | Cookie 检测移到 URL/Args 之后，攻击请求在 URL 阶段即短路返回 |
| **is_cdn_ip 缓存** | `trust_proxy_headers=on` 时，`is_cdn_ip()` 结果缓存到 `ngx.ctx._is_cdn`，避免同请求内重复 CIDR 匹配 |
| **内网 IP 快速短路** | 127.x/10.x/172.x/192.x 开头的 `remote_addr` 跳过 37 条 CIDR 二分查找，O(1) 判定 |
| **代理头直读** | `CF-Connecting-IP` / `X-Real-IP` / `X-Forwarded-For` 直接读 `ngx.var.http_*`，避免构造整张 headers table |
| **UA bloom-filter 预检查** | `is_white_ua()` 先检查 7 个 bot 标记词（bot/spider/crawl 等），99% 正常流量跳过 50 次 `string.find` |
| **url_args 无参数短路** | `next(REQ_ARGS) == nil` 时直接返回，跳过 `pairs()` 循环和正则匹配 |
| **最小输入长度检查** | `match_any_rule` 中 `#input < 2` 直接返回 nil，避免对短参数做正则匹配 |
| **filepath 字符串缓存** | `get_rule_entry` 缓存 `config_rule_dir .. '/' .. rulefilename` 到 worker 级变量，避免每请求字符串拼接 |
| **POST Content-Type 分流** | `application/x-www-form-urlencoded` 才走 `get_post_args()`；JSON/XML/plain body 直接走原始 body 扫描 |
| **规则匹配缓存** | 小体积请求体/参数按 `规则文件 + mtime + flags + input` 做 worker 级缓存，重复请求直接复用匹配结果 |

### 测试结果

#### 全场景压测（`test/benchmark.sh`）

##### GET

| 场景 | req/s | CPU | RSS | P99 | 吞吐下降 |
|------|-------|-----|-----|-----|---------|
| GET 基线（WAF 全关） | 27,516 | 273% | 174 MB | 43ms | — |
| GET + WAF（无 CC/POST） | 22,912 | 304% | 179 MB | 34ms | 16.7% |
| GET + WAF + CC | 23,287 | 304% | 179 MB | 30ms | 15.4% |
| GET + WAF 全开（生产） | 21,240 | 268% | 179 MB | 35ms | 22.8% |

##### form POST

| 场景 | req/s | CPU | RSS | P99 | 吞吐下降 |
|------|-------|-----|-----|-----|---------|
| form POST 基线（WAF 全关） | 31,243 | 187% | 174 MB | 27ms | — |
| form POST + WAF（CC 关闭） | 21,634 | 286% | 183 MB | 29ms | 30.7% |

##### JSON POST

| 场景 | req/s | CPU | RSS | P99 | 吞吐下降 |
|------|-------|-----|-----|-----|---------|
| JSON POST 基线（WAF 全关） | 32,188 | 192% | 174 MB | 39ms | — |
| JSON POST + WAF（CC 关闭） | 20,547 | 292% | 182 MB | 66ms | 36.2% |

> `吞吐下降` 仅在同一请求类型内计算，不再拿 GET 基线直接对比 POST 场景。

#### trust_proxy_headers 性能对比

| 场景 | req/s | TPR | P99 | 说明 |
|------|-------|-----|-----|------|
| WAF 全关（基线） | 24,366 | 4.104ms | 27ms | 无 Lua 开销 |
| `trust_proxy_headers=off` | 19,254 | 5.194ms | 25ms | 仅用 `remote_addr`，无 XFF 解析 |
| `trust_proxy_headers=on` + cdnip.rule | 18,341 | 5.452ms | 20ms | 校验来源代理是否命中 CDN IP 列表 |
| `trust_proxy_headers=on` + 无 cdnip.rule | 17,028 | 5.873ms | 33ms | 无条件信任 XFF，性能和安全性都更差 |
| `trust_proxy_headers=on` + cdnip.rule + XFF | 17,713 | 5.645ms | 25ms | 模拟真实 CDN 透传 `X-Forwarded-For` |
| `trust_proxy_headers=on` + 无 cdnip.rule + XFF | 17,060 | 5.862ms | 27ms | 无 CDN 校验时 XFF 场景仍更重 |

> **结论**：按 2026-08-20 在 `192.168.2.180` 的最新实测结果（Nginx 内存优化配置：缩小 `lua_shared_dict`、调小 buffer 尺寸、缩减 `proxy_cache_path`、关闭 `limit_conn`、`open_file_cache` 调优），NginxGuard 在 GET 常规流量下，全开但关闭 CC/POST 时吞吐下降约 **16.7%**；开启 CC 后吞吐下降约 **15.4%**。本轮 `form POST + WAF` 提升到 **21,634 req/s**，`JSON POST + WAF` 提升到 **20,547 req/s**，相比上一轮（8/19）分别从 **18,680 req/s** 和 **19,843 req/s** 继续抬升。关键优化措施：
>
> 1. **请求类型短路**：GET/HEAD/OPTIONS/DELETE 跳过 POST 和文件上传检测，避免无意义的 body 读取
> 2. **规则双引擎**：纯字符串规则用 `string.find`（快 10 倍），正则规则用合并 `ngx.re.find`，减少正则引擎负载
> 3. **配置一次加载**：所有 16 个配置项在请求入口一次性加载到 `ngx.ctx._cfg`，避免每检测项重复调用 `get_effective_config`
> 4. **解码快速特征检测**：`has_encode_markers` 使正常流量（无编码字符）跳过递归解码和 JS unicode 解码，零额外开销
> 5. **白名单 hash 优化**：`whiteua.rule`（50条纯字符串）和 `whiteurl.rule` 使用 `string.find` 替代 `ngx.re.find`，避免 PCRE JIT 开销
> 6. **空规则快速返回**：规则文件为空时 `match_any_rule` 立即返回 nil，避免无谓的 regex 编译
> 7. **Cookie 检测后移**：Cookie 检测移到 URL/Args 之后，攻击请求在 URL 阶段即可短路返回
> 8. **is_cdn_ip 请求级缓存**：`trust_proxy_headers=on` 时缓存 CDN IP 匹配结果，避免重复 CIDR 二分查找
> 9. **内网 IP 快速短路**：127.x/10.x/172.x/192.x 跳过完整 CIDR 匹配，O(1) 判定
> 10. **代理头直读**：直接读取 `ngx.var.http_cf_connecting_ip` / `http_x_real_ip` / `http_x_forwarded_for`，减少 headers table 分配
> 11. **POST Content-Type 分流**：表单请求才走 `get_post_args()`，JSON/XML/plain body 直接按原始 body 扫描
> 12. **规则匹配缓存**：重复的小体积参数/body 按 `mtime + flags + input` 复用匹配结果，显著降低 POST 热路径正则成本
>
> 本轮新增的 **Nginx 内存优化**：将 `lua_shared_dict limit`/`badGuys` 从 100m 缩减到 10m，`client_header_buffer_size` 从 1024k 缩到 1k，`large_client_header_buffers` 从 4×128k 缩到 4×8k，`client_body_buffer_size` 从 1024k 缩到 128k，`proxy_buffer_size`/`proxy_buffers` 从 64k 缩到 16k，`proxy_cache_path` 从 50m/7d/2g 缩到 10m/1d/1g，`open_file_cache` 从 100000 条缩到 10000 条。实测 WAF 关闭时内存 174MB，WAF 全开后 179-183MB，内存仅增加 5-9MB，且所有场景 P99 延迟均控制在 66ms 以内。`trust_proxy_headers=on` + `cdnip.rule` 相比 `off` 仍有额外开销，但明显优于“无 `cdnip.rule` 时无条件信任 XFF”的路径；生产环境依然建议保留 CDN IP 校验。CC 防护生效后 IP 自动封禁 600 秒，后续请求直接 403 快速返回。新增的 worker 级匹配缓存主要把收益打在重复参数和重复 body 的 POST 热路径上。

---

## 安全检测流程

每请求的检测顺序（命中任一项即拦截，后续不再执行）：

```
1. $waf_enable 检查（location 级开关，off 则跳过全部检测）
       ↓
2. waf_enable 检查（域名级/全局级开关，off 则跳过全部检测）
       ↓
3. white_ip_check     → 白名单 IP 放行
       ↓
4. dynamic_black_ip   → 动态黑名单（CC 自动拉黑期内）
       ↓
5. black_ip_check     → 静态黑名单 IP
       ↓
6. white_url_check    → 白名单 URL 放行
       ↓
7. user_agent_check   → User-Agent 攻击（白名单 UA 跳过此项）
       ↓
8. referer_check      → Referer 攻击
       ↓
9. cc_attack_check    → CC 限速
       ↓
10. file_upload_check → 文件上传扩展名（非 GET/HEAD/OPTIONS/DELETE）
       ↓
11. url_attack_check  → URL 路径攻击
       ↓
12. url_args_check    → URL 参数攻击
       ↓
13. cookie_check      → Cookie 攻击
       ↓
14. post_check        → POST 攻击（表单 + JSON body，非 GET/HEAD/OPTIONS/DELETE）
       ↓
     放行
```

> 整个流程包裹在 `pcall` 中，任何意外错误均被捕获并记录到 `ngx.log(ngx.ERR)`，不会导致 500 错误返回给客户端。
