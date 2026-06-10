# 変更履歴

このプロジェクトの全ての重要な変更は、このファイルに記録されます。

形式は [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) に基づき、
このプロジェクトは [Semantic Versioning](https://semver.org/spec/v2.0.0.html) に準拠しています。

## [未リリース]

## [0.6.0] - 2026-06-10

### 追加機能
- **MCP ツール拡張** — 従来非公開の library 関数 3 つを新 MCP ツールとして公開：
  - `check_dnssec` — カスタマイズ可能な resolver による完全 DNSSEC チェーン検証
  - `trace_resolution` — root から権威ネームサーバーまでの反復解決トレース
  - `check_propagation` — ユーザー指定の resolver リストでカスタム伝播チェック
- **伝播チェック強化** — `check_propagation_global` が `record_type` パラメータを受け入れ A・AAAA・MX・TXT 伝播確認可能に（従来は A レコード固定）
- **レイテンシ ベンチマーク改善** — `benchmark_latency` MCP ツールがユーザー指定 `transports` パラメータを処理（System/DoH/DoT/DoQ/IP）；従来は無視されていた

### 修正
- **メール セキュリティ詳細化** — DKIM チェック結果の `raw` フィールドが実際の TXT レコード値を返すように修正（従来は常に `None`）
- **ベンチマーク transport パラメータ** — `benchmark_latency` MCP ツールが `transports` 引数を完全に無視していた不具合を修正；カスタムトランスポートリストを解析・使用するように改善

## [0.5.0] - 2026-06-07

### 追加機能
- **ライブラリファースト API リデザイン** — 純 async 関数（`check_dns`、`check_tls_chain`、`check_email_security`、`check_propagation`、`benchmark_latency`）と serializable な request/response 型で AI エージェント消費を実現
- **TLS 証明書チェーン検査** — `check_tls_chain()` が TLS ハンドシェイク経由で leaf + 中間証明書をキャプチャ；x509-parser で CN・SAN・issuer・有効期限を解析
- **RFC 6698 完全 DANE/TLSA マッチング** — 6 通りの selector/matching_type 組み合わせ全サポート（selector 0/1 × matching_type 0/1/2）；SubjectPublicKeyInfo DER を `cert.public_key().raw` で抽出；sha2 crate で SHA256/SHA512 ハッシュ検証
- **メール セキュリティ検証** — `check_email_security()` で MX レコード・SPF・DKIM（4 つの標準セレクタ）・DMARC を検査；セキュリティスコア（0～100）を算出
- **DNS 伝播チェッカー** — `check_propagation()` がカスタム resolver リスト全体でドメインを照会；`check_propagation_global()` 便利関数は 6 個のグローバル resolver（Google・Cloudflare・Quad9・OpenDNS・CleanBrowsing・Comodo）をテスト
- **マルチプロトコル レイテンシ ベンチマーク** — `benchmark_latency()` が System/DoH/DoT/DoQ トランスポート間で DNS クエリレイテンシを測定；ラウンドごとに min/max/avg/success_rate をレポート
- **MCP サーバー（shohei-mcp）** — 全 library API を Claude 他 AI エージェント向け Model Context Protocol ツールとして公開；JSON-RPC 2.0 over stdio 実装；5 ツール: check_dns・check_tls_chain・check_email_security・check_propagation_global・benchmark_latency

### 変更
- **Transport 抽象化** — `Transport` enum（System・Server・Doh・Dot・Doq）と JSON-RPC/AI 統合向け serialization サポート
- **API モジュール再構成** — `src/api/` が directory に；`mod.rs`（コア）・`tls.rs`・`propagation.rs`・`email.rs`・`bench.rs` で拡張性確保
- **ドキュメント** — lib.rs とモジュール docstring をライブラリファースト利用を強調するよう更新；CLI は thin demo wrapper に

### 依存関係
- **新規**: `x509-parser` 0.16（cert フィールド解析）、`sha2` 0.10（TLSA ハッシュマッチング）、`hex` 0.4（16 進エンコーディング）、`rmcp` 1.7（MCP サーバーフレームワーク）
- **直接昇格**: `rustls` 0.23（従来は transitive）、`tokio-rustls` 0.26（従来は transitive）

## [0.4.0] - 2026-05-26

### パフォーマンス
- **DNSSEC チェーン並列化** — ゾーンごとの DS・DNSKEY クエリが `join_all` で並行実行；信頼判定の開始と同時にゾーンクエリを並行実行；典型的な 3 ゾーンチェーン（`.` → `com.` → `domain.`）の検証は従来の約 2 倍高速化
- **マルチタイプ並行クエリ** — `--type a --type aaaa --type mx` で全レコードタイプのクエリが並行実行；トランスポート設定（DoH/DoT/DoQ）は一度だけ構築され、タイプ間で `Clone` により再利用
- **グル無し NS 並列解決** — 反復トレースで未グルーのネームサーバーを順次ではなく並行（最大 5 並行）で解決
- **`hex_encode` マイクロ最適化** — バイト単位の `format!("{:02x}")` を事前計算ルックアップテーブル（`String::with_capacity` + 直接書き込み）に置き換え；DNSKEY・TLSA・SSHFP・DS レコード描画で約 5 倍のスループット向上

### 内部変更
- **`main.rs` ディスパッチ リファクタリング** — `dispatch_axfr`・`dispatch_compare_two`・`dispatch_compare_nway`・`dispatch_trace`・`dispatch_dnssec`・`dispatch_standard` 関数を抽出；`run_once` は洗練された約 20 行のディスパッチャに
- **バッチ重複排除** — ファイルモードと stdin バッチパスを単一の `run_batch()` ヘルパーに統合；約 30 行の重複コードを削減
- **`build_non_validating_resolver` 抽出** — DNSSEC チェーン構築が専用ヘルパーを使用（リゾルバ構築のインライン化を排除）

## [0.3.0] - 2026-05-21

### 追加機能
- **`--doq <IP:PORT>`** — DNS-over-QUIC トランスポート（`quic-ring` フィーチャー）
- **`--axfr`** — 専用の raw TCP 接続によるゾーン転送；`-s` が必須；500,000 レコードでキャップ；RFC 5936 に基づき SOA シリアル番号を検証
- **N-way `--compare`** — `--compare` を複数回指定して 3 台以上のサーバー比較が可能；全クエリが並行実行；サーバー単位の失敗は警告を表示して続行
- **`-4` / `-6`** — IPv4 のみまたは IPv6 のみを強制
- **`-f <FILE>` / `--file <FILE>`** — ファイルからドメイン一覧を読み込み（1 行 1 ドメイン、`dig -f` と同様）
- **HTTPS・SVCB・NAPTR レコードタイプ** — `--type` に追加；構造化表示と JSON サポート

### 修正
- **S1** — DNS TXT・CAA・NAPTR・Unknown レコードデータ内の ASCII 制御文字（`0x00–0x1f`・`0x7f`）をターミナル出力前にサニタイズ；ANSI/VT エスケープシーケンスインジェクションを防止
- **S2** — AXFR ゾーン転送を 500,000 レコードでキャップしてメモリ枯渇を防止
- **S3/B7** — stdin/ファイルバッチモード内の各ドメインを検証；無効なエントリはエラーを出力して続行；失敗があれば終了コード 1 で終了
- **B1** — AXFR が NoError 以外の RCODE（REFUSED・SERVFAIL など）で即座にエラー返却
- **B3** — N-way `--compare` がサーバー単位の失敗で警告を表示して続行；以前は最初のエラーで中止
- **B4** — ウォッチループが一時的なクエリ失敗でエラー表示とリトライから継続；以前はループを終了
- **B6** — バッチモード（stdin・`--file`）がドメインクエリ失敗時に終了コード 1 で終了
- **B8** — TUI モードが複数の `--type` フラグ指定時に警告を表示（最初のタイプのみ使用）
- **B9** — カスタム `--server` ポートが最初の接続だけでなく全 hickory 接続に適用

## [0.2.0] - 2026-05-20

### 追加機能
- **`-x` / `--reverse <IP>`** — 逆引き DNS ショートハンド：IPv4/IPv6 を PTR クエリに自動変換（`dig -x` と同様）
- **複数 `--type` フラグ** — `--type a --type aaaa --type mx` でタイプごとに 1 クエリ実行し、結果を順次レンダリング
- **stdin バッチモード** — 改行区切りのドメイン名をパイプ；`#` で始まる行はスキップ
- **DNSSEC 詳細表示（`-v` / `--verbose`）** — DNSSEC チェーンツリーにキータグ・アルゴリズム名・KSK/ZSK の種別を追加
- **TTL 人間向け表示** — テーブル出力で `300` を `5m`・`3600` を `1h`・`86400` を `1d` と表示
- README の競合比較表が doggo・q・delv・drill をカバー
- **Authority + Additional セクション** — サーバーが NS 委任またはグルーレコードを返した場合、回答テーブルの下に表示；`--no-recurse` を権威ネームサーバーに対して実行時に自動動作
- **`--no-recurse`** — RD（Recursion Desired）ビットをクリア、権威サーバーへの直接クエリが可能（`dig +norecurse` と同様）；`-s <auth-ns>` と組み合わせて Authority・Additional セクションを表示
- **`--tcp`** — DNS クエリを UDP ではなく TCP で強制（`-s` が必須；`dig +tcp` と同様）
- **CAA・TLSA・SSHFP・NSEC・NSEC3 レコードタイプ** — `--type` 列挙型に追加；CAA・TLSA・SSHFP は構造化表示と JSON サポート；NSEC/NSEC3 は hickory のネイティブ形式で表示
- **`--timeout <SECS>`** — 設定可能な DNS クエリタイムアウト（1–60 秒、デフォルト 5、以前はハードコード）

### 修正
- `build_chain` と `trace` の呼び出し箇所の統合テストが欠落していた `Option<IpAddr>` 引数に対応

## [0.1.0] - 2026-05-15

### 追加機能
- DNS クエリの基本実装とカラーテーブル出力（`A`・`AAAA`・`MX`・`NS`・`TXT`・`CNAME`・`SOA`・`PTR`・`SRV`・`DNSKEY`・`DS`・`RRSIG`）
- DNSSEC 信頼の連鎖ビジュアル化（`--dnssec`）
- ルートサーバーからの反復解決パストレース（`--trace`）
- DNS-over-HTTPS サポート（`--doh`）
- DNS-over-TLS サポート（`--dot`）
- スクリプト向け JSON 出力（`--output json`）
- CI 環境向けプレーンテキスト出力（`--output plain`）
- カスタムリゾルバアドレス（`--server`）
- `indicatif` によるプログレススピナー
