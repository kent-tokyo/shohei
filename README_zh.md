# shohei

[![Crates.io](https://img.shields.io/crates/v/shohei.svg)](https://crates.io/crates/shohei)
[![CI](https://github.com/kent-tokyo/shohei/actions/workflows/ci.yml/badge.svg)](https://github.com/kent-tokyo/shohei/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MSRV](https://img.shields.io/badge/rust-1.75%2B-blue.svg)](https://www.rust-lang.org)

[English](README.md) | [日本語](README_ja.md)

**shohei** 是下一代 DNS 诊断命令行工具。它不仅仅是 `dig` 的替代品，还能将从根到答案的完整 **DNSSEC 信任链（Chain of Trust）**、逐跳迭代解析路径以及 **DoH / DoT** 现代传输协议以彩色树状结构直接渲染在终端中。

- **DNSSEC 信任链树** — 可视化从 `.` 到目标域名每个 DS、DNSKEY 步骤
- **迭代解析追踪** — 展示从根服务器 → TLD → 权威 NS 的完整查询路径
- **双服务器对比** — 使用 `--compare` 并排对比两个解析器的结果
- **DoH / DoT 支持** — 内置 DNS-over-HTTPS 和 DNS-over-TLS
- **JSON 输出** — 适用于脚本和自动化的管道友好输出
- **监控模式** — 使用 `--watch` 定期自动刷新
- **精简输出** — 使用 `--short` 每行仅输出数据值（适用于脚本）
- **交互式 TUI** — 在单个终端窗口中浏览记录、DNSSEC 链和追踪结果（`--features tui`）

## 为什么选择 shohei？

| 功能 | shohei | dig | dog |
|------|:------:|:---:|:---:|
| 彩色表格输出 | ✓ | | ✓ |
| DNSSEC 信任链树 | **✓** | | |
| 迭代解析追踪 | **✓** | | |
| 双服务器对比 (`--compare`) | **✓** | | |
| 监控模式 (`--watch`) | **✓** | | |
| 精简输出 (`--short`) | **✓** | | |
| DNS-over-HTTPS (DoH) | ✓ | ✓ | ✓ |
| DNS-over-TLS (DoT) | ✓ | ✓ | ✓ |
| JSON 输出 | ✓ | | ✓ |
| 交互式 TUI | **✓** | | |

![DNSSEC 信任链](images/demo_dnssec.svg)

## 演示

### 迭代解析追踪
![迭代解析追踪演示](images/demo-trace.gif)

### 监控模式
![监控模式演示](images/demo-watch.gif)

### 交互式 TUI
![TUI 演示](images/demo-tui.gif)

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
```

![DNS 记录查询](images/demo_basic.svg)

![MX 记录](images/demo_mx.svg)

### DNSSEC 信任链

验证从根信任锚到目标域名的完整 DNSSEC 链，逐区域检查 DS 和 DNSKEY 记录。

```bash
shohei cloudflare.com --dnssec
```

![DNSSEC 信任链](images/demo_dnssec.svg)

### 迭代解析追踪

逐步展示完整解析路径：根服务器 → TLD 名称服务器 → 权威名称服务器。

```bash
shohei google.com --trace
```

![迭代解析追踪](images/demo_trace.svg)

### 现代传输协议

```bash
# DNS-over-HTTPS
shohei google.com --doh https://dns.google/dns-query

# DNS-over-TLS
shohei google.com --dot 1.1.1.1:853

# 自定义解析器
shohei google.com --server 8.8.8.8
```

### 精简输出

去除所有装饰，仅输出记录数据值，每行一条。非常适合 Shell 脚本处理。

```bash
shohei gmail.com --type MX --short
```

![精简输出](images/demo_short.svg)

### 双服务器对比

同时向两个 DNS 服务器查询同一域名，并对比差异。适用于检测 CDN 任播差异或验证新解析器。

```bash
# 验证两个服务器返回相同的 NS 记录
shohei cloudflare.com --type NS --server 8.8.8.8 --compare 1.1.1.1

# 发现 CDN 导致的 A 记录差异
shohei google.com --server 8.8.8.8 --compare 1.1.1.1
```

![对比 — 结果一致](images/demo_compare_match.svg)

![对比 — 存在差异](images/demo_compare_diff.svg)

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
| `--type <TYPE>` | `-t` | 记录类型：`a`, `aaaa`, `mx`, `ns`, `txt`, `cname`, `soa`, `ptr`, `srv`, `dnskey`, `ds`, `rrsig`, `any` |
| `--dnssec` | `-d` | 显示 DNSSEC 信任链验证树 |
| `--trace` | | 显示从根服务器开始的迭代解析路径 |
| `--short` | | 仅输出数据值，每行一条（适用于脚本） |
| `--watch <SECS>` | | 每隔 N 秒重复查询（Ctrl+C 停止） |
| `--compare <ADDR>` | | 向第二个服务器查询并对比差异 |
| `--doh <URL>` | | DNS-over-HTTPS（例如 `https://dns.google/dns-query`） |
| `--dot <IP:PORT>` | | DNS-over-TLS（例如 `1.1.1.1:853`） |
| `--server <ADDR>` | `-s` | 自定义 DNS 服务器（`8.8.8.8` 或 `8.8.8.8:53`） |
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
