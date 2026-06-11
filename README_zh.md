# shohei

[![Crates.io](https://img.shields.io/crates/v/shohei.svg)](https://crates.io/crates/shohei)
[![CI](https://github.com/kent-tokyo/shohei/actions/workflows/ci.yml/badge.svg)](https://github.com/kent-tokyo/shohei/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MSRV](https://img.shields.io/badge/rust-1.85%2B-blue.svg)](https://www.rust-lang.org)

[English](README.md) | [日本語](README_ja.md)

**shohei** v2.2.0 — **140 MCP 工具 × 56 模块**的 Rust 基础设施诊断库。全面的安全、OSINT、威胁情报和治理功能。DNS、TLS、邮件安全、DNS 传播、IPv6 双栈、安全头自动检查。**API 密钥零需求 — 完全免费、开源 API 专用**。可集成到 Rust 项目，也可与 AI 代理协作。

- **Claude MCP 服务器** — 从 Claude Desktop 调用 **140 个工具**。告诉 Claude「检查 example.com 的安全性」即可自动诊断 TLS、邮件、DNS、IPv6、RPKI、威胁情报
- **TLS 证书检查** — DANE/TLSA 验证（RFC 6698 全部 6 种组合）、证书链分析、OCSP 响应钉扎检测、TLS 版本检测（1.0～1.3）、暗号套件枚举
- **邮件安全评分** — MX/SPF/DKIM/DMARC/BIMI/MTA-STS/TLS-RPT 验证，0～100 合规度评分
- **安全头审计** — CSP、HSTS、X-Frame-Options、X-Content-Type-Options、Referrer-Policy、Permissions-Policy 检查和风险评估
- **DNS 传播检查** — 6 大全球解析器（Google、Cloudflare、Quad9 等）一致性确认
- **延迟基准测试** — System、DoH、DoT、DoQ 多轮次响应时间测量
- **DNSSEC 信任链树** — 可视化从 `.` 到目标域名每个 DS、DNSKEY 步骤（各区域并发验证）；`-v` 显示密钥标签和算法名称
- **IPv6 双栈验证** — AAAA 记录确认、IPv6 TCP/TLS/HTTP 连通性检查、双栈完整性判定
- **N 路服务器对比** — 多次指定 `--compare` 可同时对比任意数量的解析器
- **DoH / DoT / DoQ 支持** — 内置 DNS-over-HTTPS、DNS-over-TLS 和 DNS-over-QUIC
- **区域传输（AXFR）** — 使用 `--axfr` 从权威服务器获取完整区域数据
- **端口扫描** — 15 个常用端口（SSH/22、HTTP/80、HTTPS/443、MySQL/3306 等）的 TCP 连接 + 横幅抓取
- **RPKI/ROA 验证** — BGP 起源授权检查，防劫持耐力评估
- **DNS 放大系数计测** — UDP 查询/响应大小比计测，DDoS 踏脚石风险评估
- **通配符 DNS 检测** — `*.domain` 误配置检测
- **跟踪路由/跳转分析** — 多平台支持的跳跳延迟测量

## 为什么选择 shohei？

### AI-First 基础设施诊断

大多数基础设施工具仅限 CLI。**shohei 为 AI 代理而生：**

- **MCP 服务器就绪**: 无需代码即可从 Claude、ChatGPT 和自定义 AI 代理调用全部功能
- **Claude Desktop 集成**: 告诉 Claude「检查 example.com 的 TLS 证书」→ 自动诊断返回完整链分析
- **结构化异步 API**: 所有函数返回可 Serde 序列化的类型（`DnsCheckResult`、`TlsCheckResult`、`EmailSecurityResult`）— 为 AI 代理优化
- **无 CLI、无 Python**: 纯 Rust 库 + MCP 服务器；从单次检查到自动监控任意规模

### 开发者友好

- **库优先设计**: 集成到 Rust 项目、CI/CD 管道或自动化框架
- **信任链验证**: 唯一能在一次调用中验证 DNS → DNSSEC → TLS → DANE/TLSA 的开源库
- **现代协议**: DoH、DoT、DoQ、DNSSEC、DANE/TLSA 全部内置
- **自动化友好**: 并发查询、批处理、多解析器同时检查、编程式 API

**与其他工具对比**（`dig`、`dog`、`drill`）：shohei 可组合 — 用于测试、监控、CI/CD，**或交给 Claude 进行自动诊断**。

| 功能 | shohei | dig | dog | doggo | q | delv | drill |
|------|:------:|:---:|:---:|:-----:|:-:|:----:|:-----:|
| 彩色输出 | ✓ | | ✓ | ✓ | ✓ | | |
| **DNSSEC 信任链树** | **✓** | | | | | | |
| DNSSEC 验证 | ✓ | ✓ | | | | ✓ | ✓ |
| **迭代解析追踪（可视化）** | **✓** | | | | | | |
| Authority + Additional 区段 | ✓ | ✓ | | | | ✓ | ✓ |
| N 路服务器对比 (`--compare`) | **✓** | | | | | | |
| 区域传输（AXFR） | **✓** | ✓ | | | | | ✓ |
| 监控模式 (`--watch`) | **✓** | | | | | | |
| 精简输出 (`--short`) | **✓** | | | | | | |
| **多记录类型同时查询** (`--type a --type mx`) | **✓** | | | ✓ | | | |
| **反向 DNS 简写** (`-x 1.2.3.4`) | **✓** | ✓ | | ✓ | | | |
| 强制 TCP (`--tcp`) | ✓ | ✓ | | | | | ✓ |
| 禁用递归 (`--no-recurse`) | ✓ | ✓ | | | | ✓ | ✓ |
| 查询延迟显示 | ✓ | ✓ | | ✓ | ✓ | | |
| DNS-over-HTTPS (DoH) | ✓ | ✓ | ✓ | ✓ | ✓ | | |
| DNS-over-TLS (DoT) | ✓ | ✓ | ✓ | ✓ | ✓ | | |
| DNS-over-QUIC (DoQ) | **✓** | | | | ✓ | | |
| JSON 输出 | ✓ | ✓ | ✓ | ✓ | ✓ | | |
| 交互式 TUI | **✓** | | | | | | |

> dig = BIND utils 9.16+; q = [natesales/q](https://github.com/natesales/q); delv = BIND DNSSEC 验证解析器; drill = 基于 ldns

## MCP 安全服务器对比

shohei v2.2.0 是功能最全面、完全免费、无需 API 密钥的 MCP 安全服务器：

| 功能 | shohei | honeylabs | kastell | unphurl | cloud-audit | maigret |
|------|:------:|:---------:|:-------:|:-------:|:-----------:|:-------:|
| **MCP 工具数** | **140** | ~25 | ~30 | ~15 | ~20 | ~35 |
| **模块数** | **56** | ~8 | ~10 | ~5 | ~7 | ~12 |
| **DNS/DNSSEC** | ✓ | ✓ | ✓ | | | |
| **TLS/证书** | ✓ | ✓ | ✓ | | | |
| **邮件安全** | ✓ | | | | | |
| **OSINT/侦察** | ✓ | ✓ | | ✓ | | ✓ |
| **威胁情报** | ✓ | | | | | |
| **WHOIS/域名** | ✓ | | ✓ | | | |
| **端口/服务** | ✓ | | | | | |
| **IP 声誉** | ✓ | ✓ | | | | |
| **合规性/治理** | ✓ | | | | ✓ | |
| **加密货币/区块链** | ✓ | | | | | |
| **网络头** | ✓ | ✓ | | ✓ | | |
| **所需 API 密钥数** | **0** | 多个 | 多个 | 若干 | 多个 | 多个 |
| **仅免费/开源 API** | **✓** | 部分 | 部分 | 部分 | 部分 | 部分 |
| **活跃维护** | ✓ | | | | | ✓ |
| **开源** | ✓ (MIT) | | | | | ✓ |

**主要优势：**
- **140 MCP 工具** — 最大的综合安全工具包（v2.2.0）
- **0 API 密钥** — 所有工具使用免费/开源公共 API
- **56 模块** — DNS、TLS、邮件、OSINT、威胁情报、治理、加密货币、Web 安全、合规性
- **零设置成本** — 无需供应商 API 账户或身份验证
- **纯库 + MCP** — CI/CD 用 Rust 库 + Claude Desktop/代理用 MCP 服务器


## 安装

```bash
cargo install shohei
```

启用交互式 TUI 模式：

```bash
cargo install shohei --features tui
```

或从[发布页面](https://github.com/kent-tokyo/shohei/releases)下载预编译二进制文件。

## 使用方法

### DNS 记录查询

```bash
shohei google.com              # A 记录（默认）
shohei google.com --type AAAA  # AAAA 记录
shohei google.com --type NS    # 名称服务器
shohei gmail.com  --type MX    # 邮件交换记录

# 一次查询多种记录类型
shohei google.com --type a --type aaaa --type mx
```



```bash
# 安全 / DNSSEC 相关记录类型
shohei google.com --type caa       # 证书颁发机构授权（CAA）
shohei github.com --type sshfp     # SSH 指纹
shohei _443._tcp.example.com --type tlsa  # DANE TLSA
```


### 反向 DNS

解析 IP 地址的 PTR 记录，支持 IPv4 和 IPv6。

```bash
shohei -x 1.1.1.1              # → one.one.one.one
shohei -x 2606:4700:4700::1111 # IPv6 反向解析
```

### DNSSEC 信任链

验证从根信任锚到目标域名的完整 DNSSEC 链，逐区域检查 DS 和 DNSKEY 记录。

```bash
shohei cloudflare.com --dnssec

# 详细模式：显示密钥标签、算法名称和 KSK/ZSK 类型
shohei cloudflare.com --dnssec --verbose
```


### 迭代解析追踪

逐步展示完整解析路径：根服务器 → TLD 名称服务器 → 权威名称服务器。

```bash
shohei google.com --trace
```


### 现代传输协议

```bash
# DNS-over-HTTPS
shohei google.com --doh https://dns.google/dns-query

# DNS-over-TLS
shohei google.com --dot 1.1.1.1:853

# DNS-over-QUIC
shohei google.com --doq 8.8.8.8

# 自定义解析器
shohei google.com --server 8.8.8.8
```

### Authority 和 Additional 区段

直接查询权威服务器时，shohei 显示 **Authority Section**（NS 委派）和 **Additional Section**（胶水 A/AAAA 记录）——与 `dig` 默认行为一致。

```bash
# 查询 .com TLD 名称服务器中的 google.com — 显示 NS 委派和胶水记录
shohei google.com -s 192.5.6.30 --no-recurse

# 直接查询权威名称服务器
shohei example.com -s 199.43.135.53 --no-recurse --type ns
```


### 强制 TCP

强制使用 TCP 而非 UDP 发送 DNS 查询。适用于响应被截断或 UDP/53 被封锁的环境。

```bash
shohei example.com -s 8.8.8.8 --tcp
```

### 精简输出

去除所有装饰，仅输出记录数据值，每行一条。非常适合 Shell 脚本处理。

```bash
shohei gmail.com --type MX --short
```


### 服务器对比

同时向多个 DNS 服务器查询同一域名，并对比差异。适用于检测 CDN 任播差异或验证新解析器。多次指定 `--compare` 可进行 N 路对比。

```bash
# 验证两个服务器返回相同的 NS 记录
shohei cloudflare.com --type NS --server 8.8.8.8 --compare 1.1.1.1

# 发现 CDN 导致的 A 记录差异
shohei google.com --server 8.8.8.8 --compare 1.1.1.1

# 三路对比
shohei google.com --server 8.8.8.8 --compare 1.1.1.1 --compare 9.9.9.9
```



### 区域传输（AXFR）

从权威服务器获取完整的区域数据。需要使用 `-s` 指定权威名称服务器。

```bash
shohei zonetransfer.me --axfr -s 81.4.108.41
```


### 批量 / stdin 模式

通过管道传入以换行符分隔的域名列表，shohei 将依次查询每个域名。
以 `#` 开头的行将被忽略（注释）。也可以使用 `-f` 从文件读取。

```bash
echo -e "google.com\nexample.com\ncloudflare.com" | shohei
cat domains.txt | shohei --type mx --short
shohei -f domains.txt --type mx --short
```

### 监控模式

每隔 N 秒重复查询并自动刷新显示。按 Ctrl+C 停止。

```bash
shohei google.com --watch 5         # 每 5 秒刷新一次
shohei google.com --type A --watch 10
```

### 输出格式

```bash
shohei google.com --output json   # JSON 格式（适用于脚本）
shohei google.com --output plain  # 无颜色输出（适用于 CI 环境）
```

### 交互式 TUI（需要 `--features tui`）

并行预加载记录、DNSSEC 链和迭代追踪，然后以可切换的视图呈现。

```bash
shohei google.com --tui
```

```
 shohei — google.com
┌─ Records ──────────────────────────────────────────────────────────┐
│ Query: google.com (A IN)                                           │
│                                                                    │
│ NAME                                    TTL   TYPE   DATA          │
│ ────────────────────────────────────────────────────────────────── │
│ google.com.                             120   A      142.250.x.x   │
│ ...                                                                │
└────────────────────────────────────────────────────────────────────┘
 [r] Records  [d] DNSSEC  [t] Trace  [↑↓/jk] Scroll  [q] Quit
```

| 按键 | 操作 |
|------|------|
| `r` | 记录视图 |
| `d` | DNSSEC 信任链视图 |
| `t` | 迭代追踪视图 |
| `↑` / `k` | 向上滚动 |
| `↓` / `j` | 向下滚动 |
| `q` / `Esc` | 退出 |

## 选项

| 参数 | 缩写 | 说明 |
|------|------|------|
| `--type <TYPE>` | `-t` | 记录类型（可重复）：`a`, `aaaa`, `mx`, `ns`, `txt`, `cname`, `soa`, `ptr`, `srv`, `https`, `svcb`, `naptr`, `dnskey`, `ds`, `rrsig`, `caa`, `tlsa`, `sshfp`, `nsec`, `nsec3`, `any` |
| `--reverse <IP>` | `-x` | 反向 DNS — 自动将 IP 转换为 PTR 查询（支持 IPv4/IPv6） |
| `--file <FILE>` | `-f` | 从文件读取域名列表（每行一个），类似 `dig -f` |
| `--dnssec` | `-d` | 显示 DNSSEC 信任链验证树 |
| `--verbose` | `-v` | 显示详细信息（DNSSEC 链中的密钥标签和算法） |
| `--trace` | | 显示从根服务器开始的迭代解析路径 |
| `--no-recurse` | | 清除 RD 位 — 直接查询权威服务器；显示 Authority + Additional 区段 |
| `--axfr` | | 从 `-s` 指定的服务器执行区域传输（AXFR） |
| `--tcp` | | 强制使用 TCP（需要 `-s`；适用于大型/截断响应） |
| `--timeout <SECS>` | | DNS 查询超时秒数（默认: 5，最大: 60） |
| `--short` | | 仅输出数据值，每行一条（适用于脚本） |
| `--watch <SECS>` | | 每隔 N 秒重复查询（Ctrl+C 停止） |
| `--compare <ADDR>` | | 向额外服务器查询并对比；可重复指定进行 N 路对比 |
| `--doh <URL>` | | DNS-over-HTTPS（例如 `https://dns.google/dns-query`） |
| `--dot <IP:PORT>` | | DNS-over-TLS（例如 `1.1.1.1:853`） |
| `--doq <IP:PORT>` | | DNS-over-QUIC（例如 `8.8.8.8` 或 `8.8.8.8:853`） |
| `--server <ADDR>` | `-s` | 自定义 DNS 服务器（`8.8.8.8` 或 `8.8.8.8:53`） |
| `-4` | | 强制使用 IPv4 传输 |
| `-6` | | 强制使用 IPv6 传输 |
| `--output <FORMAT>` | `-o` | `colored`（默认）· `plain` · `json` |
| `--tui` | | 交互式 TUI（需要 `--features tui`） |

## 信任状态

| 标识 | 含义 |
|------|------|
| `✓ SECURE` | DNSSEC 验证通过，完整信任链已确认 |
| `⚠ INSECURE` | 区域未签名，但父区域无 DS 记录（预期行为） |
| `✗ BOGUS` | 验证失败 — 签名不匹配或信任链断裂 |
| `? INDETERMINATE` | 未请求验证或结果不明确 |

## MCP 服务器 & Claude 集成

### ✅ v2.2.0+ 已完成实现

**MCP（Model Context Protocol）服务器**（140 工具）让 Claude Desktop 和其他 AI 代理能直接调用 shohei 诊断：

```bash
# 1. 安装 shohei
cargo install shohei

# 2. 注册 MCP 服务器到 Claude Desktop 配置：
# ~/.config/Claude/claude_desktop_config.json
{
  "mcpServers": {
    "shohei": {
      "command": "/path/to/shohei-mcp"
    }
  }
}

# 3. 重启 Claude Desktop
# 4. 问 Claude：「检查 example.com 的 TLS 证书」
```

**提供给 Claude 的 140 个工具（56 模块）：**
- **DNS & DNSSEC**（10+ 工具）— 记录查询、DNSSEC 验证、传播检查、区域传输、延迟基准测试
- **TLS & 证书**（8+ 工具）— 链检查、DANE/TLSA 验证、证书透明度（CT）日志、OCSP 检查、密码套件
- **邮件安全**（6+ 工具）— SPF、DKIM、DMARC、BIMI、MTA-STS、TLS-RPT 验证和合规评分
- **IP & 网络**（10+ 工具）— IP 声誉、反向 DNS、ASN/GeoIP、端口扫描、跟踪路由、IPv6 双栈检查
- **网络安全**（12+ 工具）— 安全头审计、WAF/CDN 检测、技术栈识别、HTTP/2/3 检测、重定向分析
- **OSINT & 侦察**（15+ 工具）— WHOIS、域名年龄、子域列举、仿冒域名检测、泊车域名检测、品牌名检查器
- **威胁情报**（10+ 工具）— CVE 查询、VirusTotal 集成、URLhaus 检查、Shodan 查询、数据泄露数据库查询
- **治理 & 合规性**（8+ 工具）— BGP/RPKI 验证、GDPR 合规检查、邮件认证链（ARC）、DNS 放大风险
- **加密货币 & 区块链**（10+ 工具）— 以太坊地址验证、加密货币持有者检测、区块链 WHOIS
- **高级分析**（19+ 工具）— 实体关系图、品牌检测、URL 分析、重定向源域名年龄、合规报告、HASSH 指纹识别、云暴露、网络信誉
- **URL 智能**（4 工具）— URL 解析、安全智能、篡改检测、分析
- **云暴露**（4 工具）— 云提供商资产检测、配置误差扫描、云基础设施分析
- **OSINT 扩展**（4 工具）— 高级侦察技术、基础设施映射、历史数据查询
- **网络信誉**（3 工具）— ISP 信誉、网络行为分析、威胁评分

**示例：** Claude 自动诊断域名：
> 「检查 example.com 的邮件配置是否正确，验证其 TLS 证书链」
> → Claude 调用 check_email_security + check_tls_chain → 返回完整分析

![Claude Desktop 中使用 shohei MCP](images/use_mcp_shohei_01.png)

### 其他集成方式

- **Rust 库**: 在项目中 `use shohei;` — 结构化异步 API
- **CLI**: 手动诊断：`shohei example.com --dnssec --trace`
- **JSON 输出**: 脚本和自动化：`shohei example.com --output json`

## 使用的 Crate

- [hickory-dns](https://hickory-dns.org/) — DNSSEC、DoH、DoT 支持
- [clap](https://crates.io/crates/clap) — CLI 参数解析
- [ratatui](https://ratatui.rs/) — TUI 框架（可选 `tui` 特性）
- [owo-colors](https://crates.io/crates/owo-colors) — 终端颜色
- [comfy-table](https://crates.io/crates/comfy-table) — 记录表格渲染

## 许可证

MIT — 详见 [LICENSE](LICENSE)
