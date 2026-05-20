# shohei

[![Crates.io](https://img.shields.io/crates/v/shohei.svg)](https://crates.io/crates/shohei)
[![CI](https://github.com/kent-tokyo/shohei/actions/workflows/ci.yml/badge.svg)](https://github.com/kent-tokyo/shohei/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MSRV](https://img.shields.io/badge/rust-1.75%2B-blue.svg)](https://www.rust-lang.org)

[English](README.md) | [中文](README_zh.md)

**shohei** は次世代のDNS診断CLIツールです。単なる `dig` の代替にとどまらず、ルートから最終回答までの **DNSSEC 信頼の連鎖（Chain of Trust）**、ホップごとの反復解決パス、そして **DoH / DoT** によるモダントランスポートをカラーツリーとしてターミナルに表示します。

- **DNSSEC チェーンツリー** — `.` から対象ドメインまで DS・DNSKEY の各ステップを可視化；`-v` でキータグ・アルゴリズム名も表示
- **反復解決トレース** — ルートサーバー → TLD → 権威NSへのクエリ経路をステップ表示
- **Authority + Additional セクション** — 権威サーバーへの直接クエリで NS 委任とグルーレコードを表示
- **2サーバー比較** — `--compare` で2つのリゾルバの結果を並べて差分表示
- **DoH / DoT 対応** — DNS-over-HTTPS / DNS-over-TLS をビルトインサポート
- **複数レコードタイプ** — `--type a --type aaaa --type mx` で1コマンドで一括取得
- **逆引き DNS** — `-x 1.2.3.4` で IPv4/IPv6 の PTR レコードをすぐ解決
- **stdin バッチモード** — ドメイン一覧をパイプして一括クエリ
- **TTL 人間向け表示** — `300` を `5m`、`3600` を `1h` と表示
- **JSON 出力** — スクリプト・自動化に対応したパイプフレンドリーな出力
- **ウォッチモード** — `--watch` で定期的に自動更新
- **短縮出力** — `--short` でデータ値のみを1行ずつ表示（シェルスクリプト向け）
- **インタラクティブ TUI** — レコード・DNSSEC チェーン・トレースを1画面で閲覧 (`--features tui`)

## なぜ shohei？

DNS ツールは大きく3つに分類されます。生のテキスト出力に留まるクラシック系（`dig`・`drill`・`delv`）、カラフルな表示とモダントランスポートを追加した新世代系（`dog`・`doggo`・`q`）、そしてその両方を兼ね備えた上で、他のどのツールにもない **DNSSEC 信頼の連鎖のビジュアル可視化** と **注釈付き反復解決トレース** を提供する shohei です。

| 機能 | shohei | dig | dog | doggo | q | delv | drill |
|------|:------:|:---:|:---:|:-----:|:-:|:----:|:-----:|
| カラー出力 | ✓ | | ✓ | ✓ | ✓ | | |
| **DNSSEC 信頼の連鎖ツリー** | **✓** | | | | | | |
| DNSSEC 検証 | ✓ | ✓ | | | | ✓ | ✓ |
| **反復解決トレース（可視化）** | **✓** | | | | | | |
| Authority + Additional セクション | ✓ | ✓ | | | | ✓ | ✓ |
| 2サーバー比較 (`--compare`) | **✓** | | | | | | |
| 自動更新 (`--watch`) | **✓** | | | | | | |
| 短縮出力 (`--short`) | **✓** | | | | | | |
| **複数レコードタイプ一括クエリ** (`--type a --type mx`) | **✓** | | | ✓ | | | |
| **逆引きショートハンド** (`-x 1.2.3.4`) | **✓** | ✓ | | ✓ | | | |
| TCP 強制 (`--tcp`) | ✓ | ✓ | | | | | ✓ |
| 再帰無効 (`--no-recurse`) | ✓ | ✓ | | | | ✓ | ✓ |
| クエリ応答速度表示 | ✓ | ✓ | | ✓ | ✓ | | |
| DNS-over-HTTPS (DoH) | ✓ | ✓ | ✓ | ✓ | ✓ | | |
| DNS-over-TLS (DoT) | ✓ | ✓ | ✓ | ✓ | ✓ | | |
| DNS-over-QUIC (DoQ) | | | | | ✓ | | |
| JSON 出力 | ✓ | ✓ | ✓ | ✓ | ✓ | | |
| インタラクティブ TUI | **✓** | | | | | | |

> dig = BIND utils 9.16+; q = [natesales/q](https://github.com/natesales/q); delv = BIND DNSSEC 検証リゾルバ; drill = ldns ベース; DoQ は hickory QUIC 対応後に実装予定

![DNSSEC 信頼の連鎖](images/demo_dnssec.svg)

## デモ

### 反復解決トレース
![反復解決トレース デモ](images/demo-trace.gif)

### ウォッチモード
![ウォッチモード デモ](images/demo-watch.gif)

### インタラクティブ TUI
![TUI デモ](images/demo-tui.gif)

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

# 複数タイプを1コマンドで一括取得
shohei google.com --type a --type aaaa --type mx
```

![DNS レコードクエリ](images/demo_basic.svg)

![MX レコード](images/demo_mx.svg)

```bash
# セキュリティ / DNSSEC 関連レコードタイプ
shohei google.com --type caa       # 認証局認可（CAA）
shohei github.com --type sshfp     # SSH フィンガープリント
shohei _443._tcp.example.com --type tlsa  # DANE TLSA
```

![CAA レコード](images/demo_caa.svg)

### 逆引き DNS

IP アドレスの PTR レコードを解決します。IPv4・IPv6 どちらも対応しています。

```bash
shohei -x 1.1.1.1              # → one.one.one.one
shohei -x 2606:4700:4700::1111 # IPv6 逆引き
```

### DNSSEC 信頼の連鎖

ルート信頼アンカーから対象ドメインまで、DNSSEC チェーン全体を検証します。
各ゾーンの DS・DNSKEY レコードを個別に確認します。

```bash
shohei cloudflare.com --dnssec

# 詳細表示: キータグ・アルゴリズム名・KSK/ZSK の種別を表示
shohei cloudflare.com --dnssec --verbose
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

### Authority・Additional セクション

権威サーバーへ直接クエリすると、**Authority Section**（NS 委任）と **Additional Section**（グルー A/AAAA レコード）が表示されます。

```bash
# .com TLD ネームサーバーに google.com を問い合わせ — NS 委任＋グルーレコードを表示
shohei google.com -s 192.5.6.30 --no-recurse

# 権威ネームサーバーへ直接問い合わせ
shohei example.com -s 199.43.135.53 --no-recurse --type ns
```

![Authority・Additional セクション](images/demo_authority.svg)

### TCP 強制

UDP の代わりに TCP で DNS クエリを送信します。大きなレスポンスが切り詰められる場合や UDP/53 がブロックされている環境で有効です。

```bash
shohei example.com -s 8.8.8.8 --tcp
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

### バッチ / stdin モード

改行区切りのドメイン一覧をパイプすると、順番にクエリを実行します。
`#` で始まる行はコメントとして無視されます。

```bash
echo -e "google.com\nexample.com\ncloudflare.com" | shohei
cat domains.txt | shohei --type mx --short
```

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
| `--type <TYPE>` | `-t` | レコードタイプ（複数可）: `a`, `aaaa`, `mx`, `ns`, `txt`, `cname`, `soa`, `ptr`, `srv`, `dnskey`, `ds`, `rrsig`, `caa`, `tlsa`, `sshfp`, `nsec`, `nsec3`, `any` |
| `--reverse <IP>` | `-x` | 逆引き — IP を PTR クエリに自動変換（IPv4・IPv6 対応） |
| `--dnssec` | `-d` | DNSSEC 信頼の連鎖の検証ツリーを表示 |
| `--verbose` | `-v` | 詳細表示（DNSSEC チェーンのキータグ・アルゴリズム等） |
| `--trace` | | ルートサーバーからの反復解決パスを表示 |
| `--no-recurse` | | RD ビットをクリア — 権威サーバーへ直接クエリ（Authority + Additional セクション表示） |
| `--tcp` | | UDP の代わりに TCP を強制（`-s` が必要；大きなレスポンスに有効） |
| `--timeout <SECS>` | | DNSクエリのタイムアウト秒数（デフォルト: 5、最大: 60） |
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
