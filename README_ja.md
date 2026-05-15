# shohei

[![Crates.io](https://img.shields.io/crates/v/shohei.svg)](https://crates.io/crates/shohei)
[![CI](https://github.com/kent-tokyo/shohei/actions/workflows/ci.yml/badge.svg)](https://github.com/kent-tokyo/shohei/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MSRV](https://img.shields.io/badge/rust-1.75%2B-blue.svg)](https://www.rust-lang.org)

**shohei** は次世代のDNS診断CLIツールです。単純な `dig` の代替にとどまらず、**DNSSECの信頼の連鎖（Chain of Trust）**、ルートサーバーからの反復解決パス、そして **DNS-over-HTTPS (DoH)** や **DNS-over-TLS (DoT)** などのモダンなトランスポートを可視化します。

## なぜ shohei？

現代のDNSは複雑です。DNSSEC、DoH、DoT、そして多層的な信頼チェーンは、従来のツールでのトラブルシューティングを困難にします。`shohei` はルートKSKから最終的な回答まで、信頼チェーン全体をカラーコード付きのツリーとしてターミナルに表示します。

```
DNSSEC Chain of Trust: cloudflare.com — ✓ SECURE

shohei — DNSSEC chain for cloudflare.com
├── [Trust Anchor] . — Root KSK trust anchor (RFC 8509)           ✓ SECURE
├── [DS] com. — DS record delegates trust to com.                  ✓ SECURE
├── [DNSKEY] com. — DNSKEY RRset verified for com.                ✓ SECURE
├── [DS] cloudflare.com. — DS record delegates trust               ✓ SECURE
├── [DNSKEY] cloudflare.com. — DNSKEY RRset verified              ✓ SECURE
├── [RRSIG] cloudflare.com — RRSIG covers the answer RRset        ✓ SECURE
└── [Answer] cloudflare.com — chain validation complete           ✓ SECURE
```

## インストール

```bash
cargo install shohei
```

または、[リリースページ](https://github.com/kent-tokyo/shohei/releases)からビルド済みバイナリをダウンロードしてください。

## 使い方

```bash
# Aレコードのクエリ（デフォルト）
shohei google.com

# レコードタイプを指定
shohei google.com --type MX

# DNSSEC 信頼の連鎖を検証
shohei cloudflare.com --dnssec

# ルートサーバーからの反復解決パスを追跡
shohei google.com --trace

# DNS-over-HTTPS を使用
shohei google.com --doh https://dns.google/dns-query

# DNS-over-TLS を使用
shohei google.com --dot 1.1.1.1:853

# カスタムリゾルバを使用
shohei google.com --server 8.8.8.8

# スクリプト向けにJSON出力
shohei google.com --output json

# カラーなし（CI環境向け）
shohei google.com --output plain
```

## オプション

| フラグ | 短縮 | 説明 |
|--------|------|------|
| `--type <TYPE>` | `-t` | レコードタイプ: `a`, `aaaa`, `mx`, `ns`, `txt`, `cname`, `soa`, `ptr`, `srv`, `dnskey`, `ds`, `rrsig`, `any` |
| `--dnssec` | `-d` | DNSSEC 信頼の連鎖の検証ツリーを表示 |
| `--trace` | | ルートサーバーからの反復解決パスを表示 |
| `--doh <URL>` | | DNS-over-HTTPS を使用（例: `https://dns.google/dns-query`） |
| `--dot <IP:PORT>` | | DNS-over-TLS を使用（例: `1.1.1.1:853`） |
| `--server <ADDR>` | `-s` | カスタムDNSサーバーアドレス |
| `--output <FORMAT>` | `-o` | 出力形式: `colored`（デフォルト）, `plain`, `json` |

## 信頼状態

| バッジ | 意味 |
|--------|------|
| `✓ SECURE` | DNSSECで検証済み、完全な信頼チェーンが確認済み |
| `⚠ INSECURE` | ゾーンは署名されていないが、親にDSレコードなし（想定通り） |
| `✗ BOGUS` | 検証失敗 — 署名の不一致またはチェーンの破損 |
| `? INDETERMINATE` | 検証が要求されていないか、結果が不明 |

## 使用クレート

- [hickory-dns](https://hickory-dns.org/) — DNSSEC、DoH、DoT対応
- [clap](https://crates.io/crates/clap) — CLIアーギュメント解析
- [ratatui](https://ratatui.rs/) — TUIフレームワーク（オプション機能）
- [owo-colors](https://crates.io/crates/owo-colors) — ターミナルカラー

## ライセンス

MIT — [LICENSE](LICENSE) を参照
