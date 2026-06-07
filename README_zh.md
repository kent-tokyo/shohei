# shohei

[![Crates.io](https://img.shields.io/crates/v/shohei.svg)](https://crates.io/crates/shohei)
[![CI](https://github.com/kent-tokyo/shohei/actions/workflows/ci.yml/badge.svg)](https://github.com/kent-tokyo/shohei/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MSRV](https://img.shields.io/badge/rust-1.85%2B-blue.svg)](https://www.rust-lang.org)

[English](README.md) | [日本語](README_ja.md)

**shohei** — 基础设施诊断库：**DNS**、**DNSSEC**、**TLS 证书**、**电子邮件安全**、**DNS 传播**、**DANE/TLSA** 验证。MCP 集成支持 AI 代理自动化。基于 hickory-dns 构建，提供结构化异步 API 和手动检查 CLI。

- **DNSSEC 信任链树** — 可视化从 `.` 到目标域名每个 DS、DNSKEY 步骤（各区域并发验证）；`-v` 显示密钥标签和算法名称
- **迭代解析追踪** — 展示从根服务器 → TLD → 权威 NS 的完整查询路径
- **Authority + Additional 区段** — 直接查询权威服务器时显示 NS 委派和胶水记录
- **N 路服务器对比** — 多次指定 `--compare` 可同时对比任意数量的解析器
- **DoH / DoT / DoQ 支持** — 内置 DNS-over-HTTPS、DNS-over-TLS 和 DNS-over-QUIC
- **区域传输（AXFR）** — 使用 `--axfr` 从权威服务器获取完整区域数据
- **多记录类型** — `--type a --type aaaa --type mx` 并发查询多种类型
- **反向 DNS** — `-x 1.2.3.4` 快速解析 IPv4/IPv6 的 PTR 记录
- **stdin 与文件批量模式** — 通过管道传入域名列表，或使用 `-f domains.txt`
- **TTL 人性化显示** — `300` 显示为 `5m`，`3600` 显示为 `1h`
- **JSON 输出** — 适用于脚本和自动化的管道友好输出
- **监控模式** — 使用 `--watch` 定期自动刷新
- **精简输出** — 使用 `--short` 每行仅输出数据值（适用于脚本）
- **交互式 TUI** — 在单个终端窗口中浏览记录、DNSSEC 链和追踪结果（`--features tui`）

## 为什么选择 shohei？

DNS 工具大致分为三类：输出原始文本的经典工具（`dig`、`drill`、`delv`）；增加彩色显示和现代传输协议的新一代工具（`dog`、`doggo`、`q`）；以及 shohei —— 兼具上述所有能力，并在业界首创终端原生的 **DNSSEC 信任链可视化** 与 **带注释的迭代解析追踪**。

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


## 演示

### 迭代解析追踪

### 监控模式

### 交互式 TUI

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

## 使用的 Crate

- [hickory-dns](https://hickory-dns.org/) — DNSSEC、DoH、DoT 支持
- [clap](https://crates.io/crates/clap) — CLI 参数解析
- [ratatui](https://ratatui.rs/) — TUI 框架（可选 `tui` 特性）
- [owo-colors](https://crates.io/crates/owo-colors) — 终端颜色
- [comfy-table](https://crates.io/crates/comfy-table) — 记录表格渲染

## 许可证

MIT — 详见 [LICENSE](LICENSE)
