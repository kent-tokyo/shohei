# shohei

[![Crates.io](https://img.shields.io/crates/v/shohei.svg)](https://crates.io/crates/shohei)
[![CI](https://github.com/kent-tokyo/shohei/actions/workflows/ci.yml/badge.svg)](https://github.com/kent-tokyo/shohei/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MSRV](https://img.shields.io/badge/rust-1.85%2B-blue.svg)](https://www.rust-lang.org)

[English](README.md) | [中文](README_zh.md)

> **SHOHEI** — **S**ecurity **H**ost **O**bservation & **H**ealthy **E**valuation **I**nstrument

**shohei** v2.5.1 — **168 MCP ツール × 62 モジュール**搭載 Rust インフラ診断ライブラリ。包括的なセキュリティ・OSINT・脅威インテリジェンス・ガバナンス機能。DNS・TLS・メールセキュリティ・DNS伝播・IPv6 デュアルスタック・セキュリティヘッダを自動検査。**API キー不要 — 完全無料・オープン API のみ使用**。Rust プロジェクトへの組込みも、AI エージェント連携も対応。

- **Claude MCP サーバー** — Claude Desktop から **168 個のツール**を呼び出し可能。「example.com のセキュリティをチェック」と聞けば TLS・メール・DNS・IPv6・RPKI・脅威インテリジェンスを自動診断
- **TLS 証明書検査** — DANE/TLSA 検証（RFC 6698 完全対応）、証明書チェーン分析、有効期限警告、OCSP ステープリング検出、TLS バージョン検出（1.0～1.3）、暗号スイート列挙
- **メールセキュリティスコアリング** — MX/SPF/DKIM/DMARC/BIMI/MTA-STS/TLS-RPT 検証、0～100 の準拠度スコア
- **DNS 伝播確認** — 6 大グローバルリゾルバー（Google・Cloudflare・Quad9 他）での一貫性確認
- **遅延ベンチマーク** — System・DoH・DoT・DoQ 複数ラウンドでの応答時間計測
- **DNSSEC チェーンツリー** — `.` から対象ドメインまで DS・DNSKEY の各ステップを可視化（ゾーンを並列で検証）；`-v` でキータグ・アルゴリズム名も表示
- **セキュリティヘッダ監査** — CSP・HSTS・X-Frame-Options・X-Content-Type-Options・Referrer-Policy・Permissions-Policy をチェック、リスク評価
- **IPv6 デュアルスタック検証** — AAAA レコード確認、IPv6 TCP/TLS/HTTP 疎通確認、デュアルスタック完全性判定
- **N-way サーバー比較** — `--compare` を複数回指定して何台でも同時比較
- **DoH / DoT / DoQ 対応** — DNS-over-HTTPS・DNS-over-TLS・DNS-over-QUIC をビルトインサポート
- **ゾーン転送（AXFR）** — `--axfr` で権威サーバーからゾーン全体を取得
- **ポートスキャン** — 15 個の一般的なポート（SSH/22、HTTP/80、HTTPS/443、MySQL/3306 等）への TCP 接続 + バナーグラブ
- **RPKI/ROA 検証** — BGP オリジン認可チェック、ハイジャック耐性評価
- **DNS 増幅係数計測** — UDP クエリ/レスポンスサイズ比計測、DDoS 踏み台リスク評価
- **ワイルドカード DNS 検出** — `*.domain` の誤設定検出
- **Traceroute / ホップ分析** — マルチプラットフォーム対応のホップバイホップ遅延測定

## なぜ shohei？

### AI-First インフラ診断

ほとんどのインフラツールは CLI オンリー。**shohei は AI エージェント向けに設計されています：**

- **MCP サーバー対応**: Claude・ChatGPT・カスタム AI エージェントからコード不要で全機能を呼び出し可能
- **Claude Desktop 統合**: Claude に「example.com の TLS 証明書をチェック」と依頼 → 完全なチェーン分析を自動返答
- **構造化非同期 API**: すべての関数が Serde シリアライズ可能な型を返却（`DnsCheckResult`, `TlsCheckResult`, `EmailSecurityResult`） — AI エージェント向けに最適
- **CLI 不要・Python 不要**: 純粋な Rust ライブラリ + MCP サーバー；単一チェックから自動監視まで対応

### 開発者向け機能

- **ライブラリファースト設計**: Rust プロジェクト・CI/CD パイプライン・自動化フレームワークへの組込み
- **信頼チェーン検証**: DNS → DNSSEC → TLS → DANE/TLSA を一度に検証する唯一のオープンソースライブラリ
- **モダンプロトコル**: DoH・DoT・DoQ・DNSSEC・DANE/TLSA すべて搭載
- **自動化向け**: 並列クエリ・バッチ処理・複数リゾルバー同時チェック・プログラマティック API

**他ツール（`dig`・`dog`・`drill`）との比較**: shohei は再利用可能 — テスト・監視・CI/CD・**あるいは Claude へ渡して自動診断** に対応。

| 機能 | shohei | dig | dog | doggo | q | delv | drill |
|------|:------:|:---:|:---:|:-----:|:-:|:----:|:-----:|
| カラー出力 | ✓ | | ✓ | ✓ | ✓ | | |
| **DNSSEC 信頼の連鎖ツリー** | **✓** | | | | | | |
| DNSSEC 検証 | ✓ | ✓ | | | | ✓ | ✓ |
| **反復解決トレース（可視化）** | **✓** | | | | | | |
| Authority + Additional セクション | ✓ | ✓ | | | | ✓ | ✓ |
| N-way サーバー比較 (`--compare`) | **✓** | | | | | | |
| ゾーン転送（AXFR） | **✓** | ✓ | | | | | ✓ |
| 自動更新 (`--watch`) | **✓** | | | | | | |
| 短縮出力 (`--short`) | **✓** | | | | | | |
| **複数レコードタイプ一括クエリ** (`--type a --type mx`) | **✓** | | | ✓ | | | |
| **逆引きショートハンド** (`-x 1.2.3.4`) | **✓** | ✓ | | ✓ | | | |
| TCP 強制 (`--tcp`) | ✓ | ✓ | | | | | ✓ |
| 再帰無効 (`--no-recurse`) | ✓ | ✓ | | | | ✓ | ✓ |
| クエリ応答速度表示 | ✓ | ✓ | | ✓ | ✓ | | |
| DNS-over-HTTPS (DoH) | ✓ | ✓ | ✓ | ✓ | ✓ | | |
| DNS-over-TLS (DoT) | ✓ | ✓ | ✓ | ✓ | ✓ | | |
| DNS-over-QUIC (DoQ) | **✓** | | | | ✓ | | |
| JSON 出力 | ✓ | ✓ | ✓ | ✓ | ✓ | | |
| インタラクティブ TUI | **✓** | | | | | | |

> dig = BIND utils 9.16+; q = [natesales/q](https://github.com/natesales/q); delv = BIND DNSSEC 検証リゾルバ; drill = ldns ベース
>
> **v2.4.0 追加機能**: 168 MCP ツール × 62 モジュール、robots.txt/OAuth/OIDC/API 露出検査、認証なし DB・コンテナ検出、サブドメイン乗っ取り（30+ サービス）、DGA リスクスコア、DKIM 鍵強度、攻撃面スコア、RIPE Stat パッシブ DNS、Azure AD 露出検査。
>
> **v2.5.1 セキュリティパッチ**: SSRF 脆弱性 9 件修正（CRITICAL/HIGH）— VMC フェッチ・TCP ポートスキャン・MX 接続・8 モジュールのリダイレクト追跡でバリデーション未実施。バグ修正 15 件以上（IPv6 DNSBL トレーリングドット、IDN ドメインでの Levenshtein パニック、`valid=true` を返すスタブ関数、ハードコードされた年比較、SPF `all` 修飾子が未設定のまま）。`tokio::join!` による信頼スコア・脅威スコアの 4× 高速化。

## MCP セキュリティサーバー比較表

shohei v2.5.1 は、最も包括的で無料・API キー不要の MCP セキュリティサーバーです：

| 機能 | shohei | honeylabs | kastell | unphurl | cloud-audit | maigret |
|------|:------:|:---------:|:-------:|:-------:|:-----------:|:-------:|
| **MCP ツール数** | **168** | ~25 | ~30 | ~15 | ~20 | ~35 |
| **モジュール数** | **62** | ~8 | ~10 | ~5 | ~7 | ~12 |
| **DNS/DNSSEC** | ✓ | ✓ | ✓ | | | |
| **TLS/証明書** | ✓ | ✓ | ✓ | | | |
| **メールセキュリティ** | ✓ | | | | | |
| **OSINT/偵察** | ✓ | ✓ | | ✓ | | ✓ |
| **脅威インテリジェンス** | ✓ | | | | | |
| **WHOIS/ドメイン** | ✓ | | ✓ | | | |
| **ポート/サービス** | ✓ | | | | | |
| **IP 評判** | ✓ | ✓ | | | | |
| **コンプライアンス/ガバナンス** | ✓ | | | | ✓ | |
| **仮想通貨/ブロックチェーン** | ✓ | | | | | |
| **Web ヘッダ** | ✓ | ✓ | | ✓ | | |
| **必要な API キー** | **0** | 複数 | 複数 | あり | 複数 | 複数 |
| **無料/オープン API のみ** | **✓** | 部分的 | 部分的 | 部分的 | 部分的 | 部分的 |
| **活発にメンテナンス中** | ✓ | | | | | ✓ |
| **オープンソース** | ✓ (MIT) | | | | | ✓ |

**主な利点：**
- **168 MCP ツール** — 最大級の包括的セキュリティツールキット（v2.5.1）
- **API キー不要** — すべてのツールが無料/オープン公開 API を使用
- **62 モジュール** — DNS、TLS、メール、OSINT、脅威インテリ、ガバナンス、仮想通貨、Web セキュリティ、サプライチェーン、コンプライアンス
- **ゼロセットアップコスト** — ベンダー API アカウント認証不要
- **純粋ライブラリ + MCP** — CI/CD 用 Rust ライブラリ + Claude Desktop/エージェント用 MCP サーバー


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



```bash
# セキュリティ / DNSSEC 関連レコードタイプ
shohei google.com --type caa       # 認証局認可（CAA）
shohei github.com --type sshfp     # SSH フィンガープリント
shohei _443._tcp.example.com --type tlsa  # DANE TLSA
```


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


### 反復解決トレース

ルートサーバー → TLD ネームサーバー → 権威ネームサーバーへの解決経路をステップ表示します。

```bash
shohei google.com --trace
```


### モダントランスポート

```bash
# DNS-over-HTTPS
shohei google.com --doh https://dns.google/dns-query

# DNS-over-TLS
shohei google.com --dot 1.1.1.1:853

# DNS-over-QUIC
shohei google.com --doq 8.8.8.8

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


### サーバー比較

同じドメインを複数のDNSサーバーに同時にクエリし、結果を差分表示します。CDNのエニーキャストによる差異の検出や、新しいリゾルバの検証に便利です。`--compare` を複数回指定すると N-way 比較ができます。

```bash
# 両サーバーが同じ NS レコードを返すことを確認
shohei cloudflare.com --type NS --server 8.8.8.8 --compare 1.1.1.1

# CDN によって異なる A レコードを確認
shohei google.com --server 8.8.8.8 --compare 1.1.1.1

# 3台同時比較
shohei google.com --server 8.8.8.8 --compare 1.1.1.1 --compare 9.9.9.9
```



### ゾーン転送（AXFR）

権威サーバーからゾーン全体を取得します。`-s` で権威ネームサーバーを指定する必要があります。

```bash
shohei zonetransfer.me --axfr -s 81.4.108.41
```


### バッチ / stdin モード

改行区切りのドメイン一覧をパイプすると、順番にクエリを実行します。
`#` で始まる行はコメントとして無視されます。`-f` でファイルから読み込むことも可能です。

```bash
echo -e "google.com\nexample.com\ncloudflare.com" | shohei
cat domains.txt | shohei --type mx --short
shohei -f domains.txt --type mx --short
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
| `--type <TYPE>` | `-t` | レコードタイプ（複数可）: `a`, `aaaa`, `mx`, `ns`, `txt`, `cname`, `soa`, `ptr`, `srv`, `https`, `svcb`, `naptr`, `dnskey`, `ds`, `rrsig`, `caa`, `tlsa`, `sshfp`, `nsec`, `nsec3`, `any` |
| `--reverse <IP>` | `-x` | 逆引き — IP を PTR クエリに自動変換（IPv4・IPv6 対応） |
| `--file <FILE>` | `-f` | ファイルからドメイン一覧を読み込む（dig -f 相当） |
| `--dnssec` | `-d` | DNSSEC 信頼の連鎖の検証ツリーを表示 |
| `--verbose` | `-v` | 詳細表示（DNSSEC チェーンのキータグ・アルゴリズム等） |
| `--trace` | | ルートサーバーからの反復解決パスを表示 |
| `--no-recurse` | | RD ビットをクリア — 権威サーバーへ直接クエリ（Authority + Additional セクション表示） |
| `--axfr` | | `-s` で指定したサーバーからゾーン転送（AXFR）を実行 |
| `--tcp` | | UDP の代わりに TCP を強制（`-s` が必要；大きなレスポンスに有効） |
| `--timeout <SECS>` | | DNSクエリのタイムアウト秒数（デフォルト: 5、最大: 60） |
| `--short` | | データ値のみを1行ずつ出力（スクリプト向け） |
| `--watch <SECS>` | | N秒ごとにクエリを繰り返す（Ctrl+C で停止） |
| `--compare <ADDR>` | | 追加サーバーにもクエリして差分表示；複数回指定で N-way 比較 |
| `--doh <URL>` | | DNS-over-HTTPS（例: `https://dns.google/dns-query`） |
| `--dot <IP:PORT>` | | DNS-over-TLS（例: `1.1.1.1:853`） |
| `--doq <IP:PORT>` | | DNS-over-QUIC（例: `8.8.8.8` または `8.8.8.8:853`） |
| `--server <ADDR>` | `-s` | カスタムDNSサーバー（`8.8.8.8` または `8.8.8.8:53`） |
| `-4` | | IPv4 トランスポートを強制 |
| `-6` | | IPv6 トランスポートを強制 |
| `--output <FORMAT>` | `-o` | `colored`（デフォルト）· `plain` · `json` |
| `--tui` | | インタラクティブ TUI（`--features tui` が必要） |

## 信頼状態

| バッジ | 意味 |
|--------|------|
| `✓ SECURE` | DNSSECで検証済み、完全な信頼チェーンが確認済み |
| `⚠ INSECURE` | ゾーンは未署名だが、親にDSレコードなし（想定通り） |
| `✗ BOGUS` | 検証失敗 — 署名の不一致またはチェーンの破損 |
| `? INDETERMINATE` | 検証未要求、または結果不明 |

## MCP サーバー & Claude 統合

### ✅ v2.5.1+ で実装完了

**MCP（Model Context Protocol）サーバー**（168 ツール）により、Claude Desktop と他の AI エージェントが shohei 診断を直接呼び出し可能です：

```bash
# 1. shohei をインストール
cargo install shohei

# 2. Claude Desktop 設定ファイルに登録：
# ~/.config/Claude/claude_desktop_config.json
{
  "mcpServers": {
    "shohei": {
      "command": "/path/to/shohei-mcp"
    }
  }
}

# 3. Claude Desktop を再起動
# 4. Claude に依頼：「example.com の TLS 証明書をチェック」
```

**Claude が使用可能な 168 個のツール（62 モジュール）：**
- **DNS & DNSSEC**（10+ ツール）— レコード検索、DNSSEC 検証、伝播確認、ゾーン転送、遅延ベンチマーク
- **TLS & 証明書**（8+ ツール）— チェーン検査、DANE/TLSA 検証、証明書透明性（CT）ログ、OCSP チェック、暗号スイート
- **メールセキュリティ**（6+ ツール）— SPF、DKIM、DMARC、BIMI、MTA-STS、TLS-RPT 検証と準拠度スコアリング
- **IP & ネットワーク**（10+ ツール）— IP 評判、逆引き DNS、ASN/GeoIP、ポートスキャン、トレースルート、IPv6 デュアルスタック確認
- **Web セキュリティ**（12+ ツール）— セキュリティヘッダ監査、WAF/CDN 検出、技術スタック特定、HTTP/2/3 検出、リダイレクト分析
- **OSINT & 偵察**（15+ ツール）— WHOIS、ドメイン年齢、サブドメイン列挙、タイポスクワッティング検出、駐車ドメイン検出、ブランド名チェッカー
- **脅威インテリジェンス**（10+ ツール）— CVE 検索、VirusTotal 統合、URLhaus チェック、Shodan クエリ、漏洩データベース検索
- **ガバナンス & コンプライアンス**（8+ ツール）— BGP/RPKI 検証、GDPR コンプライアンスチェック、メール認証チェーン（ARC）、DNS 増幅リスク
- **仮想通貨 & ブロックチェーン**（10+ ツール）— イーサリアムアドレス検証、仮想通貨保有者検出、ブロックチェーン WHOIS
- **高度な分析**（19+ ツール）— エンティティ関係グラフ、ブランド検出、URL 分析、リダイレクト元ドメイン年齢、コンプライアンスレポート、HASSH フィンガープリンティング、クラウド露出、ネットワーク評判
- **URL インテリジェンス**（4 ツール）— URL 解析、セキュリティインテリジェンス、改ざん検出、分析
- **クラウド露出**（4 ツール）— クラウドプロバイダーアセット検出、誤設定スキャン、クラウドインフラ分析
- **OSINT 拡張**（4 ツール）— 高度なリコン技術、インフラストラクチャマッピング、歴史的データクエリ
- **ネットワーク評判**（3 ツール）— ISP 評判、ネットワーク動作分析、脅威スコアリング
- **クラウドインフラ**（4+ ツール）— AWS/GCP/Azure リソース露出、誤設定ストレージ検出、IAM ポリシー分析
- **認証情報セキュリティ**（4+ ツール）— 漏洩認証情報チェック、API キー露出スキャン、公開リソースのシークレット検出
- **サプライチェーンセキュリティ**（4+ ツール）— 依存関係脆弱性分析、パッケージレジストリ整合性チェック、パッケージ名タイポスクワッティング
- **Web インテリジェンス**（5 ツール）— robots.txt 分析、.well-known 探索、OAuth/OIDC 監査、証明書ピニング、API デバッグエンドポイント露出
- **サービス露出検出**（4 ツール）— 無認証 DB アクセス（Redis/MongoDB/ES）、Docker/Kubernetes API 露出、バナー指紋採取、DGA リスクスコア
- **サブドメイン乗っ取り**（3 ツール）— 30+ サービスシグネチャ、RIPE Stat passive DNS、Azure AD テナント露出
- **メール詳細診断**（2 ツール）— DKIM 鍵強度（1024/2048/Ed25519）、MX サーバー STARTTLS 詳細監査
- **攻撃サーフェス**（1 ツール）— TLS + Web ヘッダー + メール + ネットワーク露出を集約した CVSS ライクな複合スコア

**例：** Claude がドメインを自動診断：
> 「example.com のメール設定が正しいか、TLS 証明書チェーンを確認して」
> → Claude が check_email_security + check_tls_chain を呼び出し → 完全な分析結果を返答

![Claude Desktop で shohei MCP を使用](images/use_mcp_shohei_01.png)

### その他の統合

- **Rust ライブラリ**: プロジェクトで `use shohei;` — 構造化非同期 API
- **CLI**: 手動検査：`shohei example.com --dnssec --trace`
- **JSON 出力**: スクリプト・自動化：`shohei example.com --output json`

## 使用クレート

- [hickory-dns](https://hickory-dns.org/) — DNSSEC、DoH、DoT 対応
- [clap](https://crates.io/crates/clap) — CLI 引数解析
- [ratatui](https://ratatui.rs/) — TUI フレームワーク（オプション `tui` フィーチャー）
- [owo-colors](https://crates.io/crates/owo-colors) — ターミナルカラー
- [comfy-table](https://crates.io/crates/comfy-table) — レコードテーブル描画

## ライセンス

MIT — [LICENSE](LICENSE) を参照
