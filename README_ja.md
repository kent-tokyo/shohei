# shohei

[![Crates.io](https://img.shields.io/crates/v/shohei.svg)](https://crates.io/crates/shohei)
[![CI](https://github.com/kent-tokyo/shohei/actions/workflows/ci.yml/badge.svg)](https://github.com/kent-tokyo/shohei/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MSRV](https://img.shields.io/badge/rust-1.75%2B-blue.svg)](https://www.rust-lang.org)

[English](README.md) | [中文](README_zh.md)

**shohei** は次世代のDNS診断CLIツールです。単なる `dig` の代替にとどまらず、ルートから最終回答までの **DNSSEC 信頼の連鎖（Chain of Trust）**、ホップごとの反復解決パス、そして **DoH / DoT** によるモダントランスポートをカラーツリーとしてターミナルに表示します。

- **DNSSEC チェーンツリー** — `.` から対象ドメインまで DS・DNSKEY の各ステップを可視化
- **反復解決トレース** — ルートサーバー → TLD → 権威NSへのクエリ経路をステップ表示
- **2サーバー比較** — `--compare` で2つのリゾルバの結果を並べて差分表示
- **DoH / DoT 対応** — DNS-over-HTTPS / DNS-over-TLS をビルトインサポート
- **JSON 出力** — スクリプト・自動化に対応したパイプフレンドリーな出力
- **ウォッチモード** — `--watch` で定期的に自動更新
- **短縮出力** — `--short` でデータ値のみを1行ずつ表示（シェルスクリプト向け）
- **インタラクティブ TUI** — レコード・DNSSEC チェーン・トレースを1画面で閲覧 (`--features tui`)

## なぜ shohei？

| 機能 | shohei | dig | dog |
|------|:------:|:---:|:---:|
| カラーテーブル出力 | ✓ | | ✓ |
| DNSSEC 信頼の連鎖ツリー | **✓** | | |
| 反復解決トレース | **✓** | | |
| 2サーバー比較 (`--compare`) | **✓** | | |
| 自動更新 (`--watch`) | **✓** | | |
| 短縮出力 (`--short`) | **✓** | | |
| DNS-over-HTTPS (DoH) | ✓ | ✓ | ✓ |
| DNS-over-TLS (DoT) | ✓ | ✓ | ✓ |
| JSON 出力 | ✓ | | ✓ |
| インタラクティブ TUI | **✓** | | |

![DNSSEC 信頼の連鎖](images/demo_dnssec.svg)

## インストール

```bash
cargo install shohei
```

インタラクティブ TUI モードを使う場合:

```bash
cargo install shohei --features tui
```

または[リリースページ](https://github.com/kent-tokyo/shohei/releases)からビルド済みバイナリをダウンロードしてください。

## 使い方

### DNSレコードクエリ

```bash
shohei google.com              # A レコード（デフォルト）
shohei google.com --type AAAA  # AAAA レコード
shohei google.com --type NS    # ネームサーバー
shohei gmail.com  --type MX    # メール交換レコード
```

![DNS レコードクエリ](images/demo_basic.svg)

![MX レコード](images/demo_mx.svg)

### DNSSEC 信頼の連鎖

ルート信頼アンカーから対象ドメインまで、DNSSEC チェーン全体を検証します。
各ゾーンの DS・DNSKEY レコードを個別に確認します。

```bash
shohei cloudflare.com --dnssec
```

![DNSSEC 信頼の連鎖](images/demo_dnssec.svg)

### 反復解決トレース

ルートサーバー → TLD ネームサーバー → 権威ネームサーバーへの解決経路をステップ表示します。

```bash
shohei google.com --trace
```

![反復解決トレース](images/demo_trace.svg)

### モダントランスポート

```bash
# DNS-over-HTTPS
shohei google.com --doh https://dns.google/dns-query

# DNS-over-TLS
shohei google.com --dot 1.1.1.1:853

# カスタムリゾルバ
shohei google.com --server 8.8.8.8
```

### 短縮出力

デコレーションを省き、レコードのデータ値のみを1行ずつ出力します。シェルスクリプトに最適です。

```bash
shohei gmail.com --type MX --short
```

![短縮出力](images/demo_short.svg)

### 2サーバー比較

同じドメインを2つのDNSサーバーに同時にクエリし、結果を差分表示します。CDNのエニーキャストによる差異の検出や、新しいリゾルバの検証に便利です。

```bash
# 両サーバーが同じ NS レコードを返すことを確認
shohei cloudflare.com --type NS --server 8.8.8.8 --compare 1.1.1.1

# CDN によって異なる A レコードを確認
shohei google.com --server 8.8.8.8 --compare 1.1.1.1
```

![比較 — 一致](images/demo_compare_match.svg)

![比較 — 差分あり](images/demo_compare_diff.svg)

### ウォッチモード

N秒ごとにクエリを繰り返し、画面を自動更新します。Ctrl+C で停止します。

```bash
shohei google.com --watch 5         # 5秒ごとに更新
shohei google.com --type A --watch 10
```

### 出力フォーマット

```bash
shohei google.com --output json   # スクリプト向け JSON
shohei google.com --output plain  # カラーなし（CI 環境向け）
```

### インタラクティブ TUI（`--features tui` が必要）

レコード・DNSSEC チェーン・トレースを並列でプリロードし、切り替え可能なビューで表示します。

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

| キー | 操作 |
|------|------|
| `r` | レコードビュー |
| `d` | DNSSEC チェーンビュー |
| `t` | 反復トレースビュー |
| `↑` / `k` | 上にスクロール |
| `↓` / `j` | 下にスクロール |
| `q` / `Esc` | 終了 |

## オプション

| フラグ | 短縮 | 説明 |
|--------|------|------|
| `--type <TYPE>` | `-t` | レコードタイプ: `a`, `aaaa`, `mx`, `ns`, `txt`, `cname`, `soa`, `ptr`, `srv`, `dnskey`, `ds`, `rrsig`, `any` |
| `--dnssec` | `-d` | DNSSEC 信頼の連鎖の検証ツリーを表示 |
| `--trace` | | ルートサーバーからの反復解決パスを表示 |
| `--short` | | データ値のみを1行ずつ出力（スクリプト向け） |
| `--watch <SECS>` | | N秒ごとにクエリを繰り返す（Ctrl+C で停止） |
| `--compare <ADDR>` | | 第2サーバーにもクエリして差分表示 |
| `--doh <URL>` | | DNS-over-HTTPS（例: `https://dns.google/dns-query`） |
| `--dot <IP:PORT>` | | DNS-over-TLS（例: `1.1.1.1:853`） |
| `--server <ADDR>` | `-s` | カスタムDNSサーバー（`8.8.8.8` または `8.8.8.8:53`） |
| `--output <FORMAT>` | `-o` | `colored`（デフォルト）· `plain` · `json` |
| `--tui` | | インタラクティブ TUI（`--features tui` が必要） |

## 信頼状態

| バッジ | 意味 |
|--------|------|
| `✓ SECURE` | DNSSECで検証済み、完全な信頼チェーンが確認済み |
| `⚠ INSECURE` | ゾーンは未署名だが、親にDSレコードなし（想定通り） |
| `✗ BOGUS` | 検証失敗 — 署名の不一致またはチェーンの破損 |
| `? INDETERMINATE` | 検証未要求、または結果不明 |

## 使用クレート

- [hickory-dns](https://hickory-dns.org/) — DNSSEC、DoH、DoT 対応
- [clap](https://crates.io/crates/clap) — CLI 引数解析
- [ratatui](https://ratatui.rs/) — TUI フレームワーク（オプション `tui` フィーチャー）
- [owo-colors](https://crates.io/crates/owo-colors) — ターミナルカラー
- [comfy-table](https://crates.io/crates/comfy-table) — レコードテーブル描画

## ライセンス

MIT — [LICENSE](LICENSE) を参照
