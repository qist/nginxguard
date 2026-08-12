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
    └── domains/                # 域名专属规则目录
        └── www.example.com/
            ├── args.rule          # URL参数攻击规则
            ├── blackip.rule       # 黑名单IP（空文件=无黑名单）
            ├── cookie.rule        # Cookie攻击规则
            ├── post.rule          # POST攻击规则
            ├── url.rule           # URL路径攻击规则
            ├── useragent.rule     # User-Agent攻击规则
            ├── whiteip.rule       # 白名单IP（空文件=无白名单）
            └── whiteurl.rule      # URL白名单
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
| `white_url_check` | 白名单 URL 检测 | `config_white_url_check` |
| `white_ip_check` | 白名单 IP 检测 | `config_white_ip_check` |
| `black_ip_check` | 黑名单 IP 检测 | `config_black_ip_check` |
| `url_check` | URL 攻击检测 | `config_url_check` |
| `url_args_check` | URL 参数检测 | `config_url_args_check` |
| `user_agent_check` | User-Agent 检测 | `config_user_agent_check` |
| `cookie_check` | Cookie 检测 | `config_cookie_check` |
| `cc_check` | CC 攻击检测 | `config_cc_check` |
| `cc_rate` | CC 限速（次数/秒数） | `config_cc_rate` |
| `cc_block_ttl` | CC 触发后自动拉黑 IP 的时长（秒），0=不自动拉黑，默认 600（10分钟） | `config_cc_block_ttl` |
| `post_check` | POST 检测 | `config_post_check` |
| `waf_output` | 拦截输出方式 | `config_waf_output` |
| `waf_redirect_url` | 跳转 URL | `config_waf_redirect_url` |
| `rule_dir` | 域名专属规则目录路径，支持绝对路径或相对路径 | （无全局对应，默认走 `config_rule_dir`） |

### 通配符域名

支持通配符域名匹配，格式为 `*.example.com`，会匹配所有子域名如 `a.test.com`、`b.test.com` 等。

匹配规则：**精确域名优先 > 通配符匹配 > 全局 config.lua**。

### 域名专属规则目录

在域名配置中设置 `rule_dir` 后，WAF 加载规则文件时会优先从该目录读取。所有 8 种规则文件都支持域名独立配置：

| 规则文件 | 检测函数 | 说明 |
|---------|---------|------|
| `whiteip.rule` | `white_ip_check()` | IP 白名单 |
| `blackip.rule` | `black_ip_check()` | IP 黑名单 |
| `whiteurl.rule` | `white_url_check()` | URL 白名单 |
| `url.rule` | `url_attack_check()` | URL 路径攻击检测 |
| `args.rule` | `url_args_attack_check()` | URL 参数攻击检测 |
| `useragent.rule` | `user_agent_attack_check()` | User-Agent 攻击检测 |
| `cookie.rule` | `cookie_attack_check()` | Cookie 攻击检测 |
| `post.rule` | `post_attack_check()` | POST 攻击检测 |

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

### 不使用域名配置

如果 `rule-config/domain.json` 文件不存在或格式错误，WAF 会自动回退到 `config.lua` 中的全局配置，行为与旧版完全一致。

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
