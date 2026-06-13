# Changelog

All notable changes to this project will be documented in this file.

## [2.5.0] - 2026-06-13

### Security

- **[CRITICAL] validate_url_safety** — Now uses `url::Url::parse` (WHATWG spec) to normalise alternative IPv4 representations (`127.1`, `2130706433`, `0x7f.0.0.1`, trailing-dot `127.0.0.1.`) before IP block-list check; all prior SSRF guards inherited this bypass
- **[CRITICAL] supply_chain** — `check_exposed_files` and `check_sbom_disclosure` were missing `validate_url_safety` on `req.domain`; added guard at function entry
- **[CRITICAL] tls** — `valid` field now performs hostname verification (SAN/CN matching with wildcard support) and self-signed detection; previously `connected && !certs.is_empty()` — any cert including self-signed or wrong-hostname returned `valid: true`, causing false PCI-DSS/HIPAA compliance passes
- **[HIGH] cdn** — `detect_cdn` SSRF guard bypassed via redirect: initial URL was validated but client followed redirects with default policy; replaced `Client::new()` with custom redirect policy that calls `validate_url_safety` per hop
- **[HIGH] mta_sts** — `fetch_mta_sts_policy` followed HTTP redirects violating RFC 8461 §3.3; added `redirect::Policy::none()`
- **[HIGH] url_intel** — `check_url_unshorten` used `Policy::limited(20)` without per-hop SSRF validation; replaced with `Policy::custom` validating each `Location` hop
- **[HIGH] cloud_security** — `check_security_txt` was missing `validate_url_safety` before HTTP fetch
- **[HIGH] subdomain_takeover_ext** — `check_subdomain_takeover` fingerprint HTTP fetch lacked `validate_url_safety`; added guard before body fetch
- **[MEDIUM] identity_security** — JWT `"none"` algorithm check was case-sensitive (`alg_val == "none"`); changed to `eq_ignore_ascii_case`; decode failure now sets `alg_secure = false`

### Fixed

- **[CRITICAL] typosquat/osint** — `detect_typosquats` in `osint.rs` used byte-index slicing (`&domain_name[..i]`) on char-iterated indices; panics on multibyte/IDN domains; replaced with char-vector indexing
- **[HIGH] tlsvuln** — DNS failure silently fell back to `IpAddr::from([0,0,0,0])`; all TLS versions falsely reported "unsupported" with no error; now returns early with descriptive error
- **[HIGH] subdomain_takeover_ext** — Fingerprint string was never compared against response body; any HTTP 4xx from a CNAME-matched subdomain was classified "high confidence vulnerable"; now reads body and matches `sig.fingerprint`
- **[HIGH] cve_lookup** — NVD description truncation used byte-index `&d.value[..200]`; panics on multibyte characters in product names; changed to `.chars().take(200).collect()`
- **[MEDIUM] identity_security** — `exp - now` i64 subtraction overflows on crafted JWT with `exp = i64::MIN`; changed to `saturating_sub`
- **[MEDIUM] trust_scoring** — `100 - threat_result.risk_score` u8 underflow when `risk_score > 100`; changed to `100u8.saturating_sub()`
- **[MEDIUM] ssh_fingerprint** — `if let Err(e) = timeout(...).await` only matched `Elapsed`; inner `io::Error` from `read_exact` fell through silently as `Ok(Err(e))`; replaced with full `match { Ok(Ok(())), Ok(Err(e)), Err(_) }` at both read sites
- **[MEDIUM] dns_amplification** — Transaction ID hardcoded to `0x1234` on every probe; replaced with `AtomicU16` monotonic counter
- **[MEDIUM] network_reputation** — `check_asn_reputation` parsed ASN number but immediately discarded it (`Ok(_) => "0.0.0.0".to_string()`); all BGP lookups queried the unspecified address; removed broken BGP lookup
- **[LOW] url_intel** — `redirect_chain` always contained only `[initial, final]`; intermediate hops were lost; now captured via `Arc<Mutex<Vec>>` in redirect policy closure
- **[LOW] url_intel** — `is_shortened = final_url != req.url` triggered false positives on URL normalisation (e.g. trailing slash added by reqwest); now compares `url::Url::parse`-normalised forms
- **[LOW] osint** — `current_year = 2026u32` hardcoded in `analyze_domain_age`; changed to `now_timestamp()` derivation
- **[LOW] zone_transfer** — AXFR receive loop had no message-count cap; adversarial server sending empty messages could spin the loop for the full timeout; added `MAX_AXFR_MESSAGES = 10_000`
- **[LOW] helpers** — `format_rfc3339` year loop could overflow `u32` and loop indefinitely on far-future timestamps; changed `loop` to `while year < 9999`

### Performance

- **trust_scoring** — `check_domain_trust_score` and `check_ip_trust_score` ran 4–5 independent API calls sequentially; replaced with `tokio::join!` for ~4× wall-clock reduction
- **ports** — `check_ports` scanned 15 ports sequentially (up to 450s worst case); replaced with `tokio::spawn` per port
- **supply_chain** — `check_exposed_files` (10 paths) and `check_sbom_disclosure` (3 paths) were sequential; parallelised with `tokio::spawn`
- **supply_chain** — `check_dependency_confusion` (npm/PyPI/crates.io) fired 3 HEAD requests sequentially; parallelised with `tokio::spawn`
- **osint** — `bruteforce_subdomains` queried 30 prefixes sequentially (up to 15 min worst case at 30s timeout); replaced with `tokio::spawn` parallel fan-out

### Refactored

- **shohei_mcp** — Replaced 168 copy-pasted `match { Ok(v) => to_string_pretty, Err(e) => json!(error) }` blocks with `api_result<T: Serialize>(r: Result<T>) -> String` helper
- **helpers** — Added `resolve_first_cname(domain, timeout) -> Option<String>` shared helper; eliminated 3 nearly-identical CNAME DNS lookup blocks across `cloud_exposure.rs` and `cloud_security.rs`
- **helpers** — Added `build_http_client(timeout_secs) -> Result<reqwest::Client>` helper centralising the 32-site reqwest client builder pattern
- **http** — `audit_security_headers` refactored from 195-line 6-block repetition to `Spec` slice + single loop; eliminates 6× O(n) header key scans (replaced with pre-lowercased `HashMap` lookup)
- **http** — `evaluate_hsts` dead else branch removed (both non-good arms returned `"weak"`)
- **tls** — Added `verify_hostname_in_cert` and `is_self_signed` helper functions; extracted from inline `valid` logic

---

## [2.4.0] - 2026-06-13

### Added

#### Phase 9: Competitor Gap-Filling (15 new tools)

**Module: web_intelligence**
- `check_robots_txt` — Fetch and parse robots.txt; identify sensitive disallowed paths (admin, backup, .git, credentials)
- `check_well_known` — Discover all accessible .well-known/ endpoints (OIDC, security.txt, JWKS, MTA-STS, SBOM, ai-plugin.json, and more)
- `check_oauth_oidc` — Audit OAuth 2.0 / OIDC configuration from .well-known/openid-configuration; detect implicit flow, PKCE support, grant types
- `check_cert_pinning` — Check Expect-CT enforce mode, HPKP remnants (deprecated), and CAA iodef reporting
- `check_api_exposure` — Probe for exposed debug/API endpoints (Spring Actuator, Swagger UI, GraphQL, phpinfo, server-status) and version disclosure headers

**Module: service_exposure**
- `check_exposed_databases` — Detect unauthenticated Redis (6379), MongoDB (27017), Elasticsearch (9200), Memcached (11211), CouchDB (5984)
- `check_container_exposure` — Detect exposed Docker API (2375/2376), Kubernetes API (6443), etcd (2379)
- `check_service_fingerprint` — Banner-based service fingerprinting for SSH, FTP, SMTP, MySQL, PostgreSQL, Redis with CVE hints
- `check_dga_risk` — Algorithmically score domain names for DGA risk (entropy, vowel ratio, digit ratio, consonant cluster analysis)

**Module: subdomain_takeover_ext**
- `check_subdomain_takeover` — Detect subdomain takeover across 30+ cloud services (GitHub Pages, Heroku, Netlify, Vercel, Azure, AWS EB, Shopify, Fastly, Tumblr, SendGrid, Mailgun, and more)
- `check_passive_dns` — Query RIPE Stat passive DNS API for historical DNS records (no API key required)
- `check_azure_ad_exposure` — Discover Azure AD / Entra ID tenant info via public Microsoft Graph endpoints (tenant ID, federation type)

**Module: email_advanced**
- `check_dkim_key_strength` — Detect weak 1024-bit DKIM RSA keys; validate 2048-bit and Ed25519 keys across common selectors
- `check_mx_security` — Deep MX server audit: STARTTLS support, ESMTP features, banner leak via live SMTP connection

**Module: dga_and_threat**
- `check_attack_surface` — Composite attack surface score (0–100): aggregates TLS, web security headers, email security, and open port exposure (CVSS-like)

### Fixed (Security)

- **[CRITICAL] SSRF prevention** — Added `validate_url_safety()` in `helpers.rs`; blocks `file://`, loopback, RFC1918, link-local (169.254.x.x) URLs
- **[CRITICAL] cloud_security** — `check_cloud_metadata_exposure` no longer queries the MCP server's own IMDS; now checks if target domain resolves to IMDS IP via DNS
- **[HIGH] identity_security** — JWT `token_valid` logic was inverted (`alg=none` returned `valid=true`); fixed to `critical_issues.is_empty() && alg_secure`
- **[HIGH] identity_security** — Cookie security score `u8` arithmetic overflow fixed (use `u32`, then clamp to 100)
- **[HIGH] shohei_mcp** — All 169 error responses now use `serde_json::json!` for proper escaping (was: unsafe `format!` with user-controlled strings)
- **[HIGH] typosquat** — IDN domain panic fixed: `remove(i)` / `insert(i, '-')` / `replace_range(i..i+1)` now use byte offsets from `char_indices()` instead of character ordinals
- **[HIGH] shohei_mcp** — `rate_limit_policy` `u32` multiplication overflow fixed with `saturating_mul`
- **[HIGH] mta_sts** — `fetch_mta_sts_policy` now uses `Client::builder().timeout()` instead of `Client::new()` (no-timeout)
- **[MEDIUM] propagation** — `check_propagation` resolver count capped at 50 to prevent unbounded `tokio::spawn` DoS
- **[MEDIUM] username_osint** — Eliminated duplicate `check_email_security` call (was making 2 identical DNS queries)

---

## [1.0.0] - 2026-06-10

### Added (v0.8.1 - v1.0.0)

#### Tier 0: Quality Fixes (v0.8.1)
- MCP tool registration for `check_rdns` (forward-confirmed reverse DNS)
- DKIM score calculation fix (proportional distribution to max 100)
- DMARC p=none validity correction (now properly marks as invalid)
- SPF/DMARC issues linting (lookup count, qualifier analysis, enforcement level)

#### Tier 1: Stub Completion (v0.8.2)
- BIMI VMC certificate validation (fetch + validity checking + PEM/DER support)
- STARTTLS reliability improvements (loop-based response reading for SMTP/IMAP/POP3)

#### Tier 2: New Features (v0.9.0-0.9.3)
- **v0.9.0**: DNSBL IP reputation checks (Spamhaus ZEN, Barracuda BRBL, SORBS)
- **v0.9.1**: CDN/WAF detection via HTTP headers (Cloudflare, AWS CloudFront, Fastly, Akamai, Vercel, Netlify, Imperva)
- **v0.9.2**: DNS delegation chain audit (SOA consistency, lame delegation detection)
- **v0.9.3**: HTTP redirect downgrade detection (HTTPS → HTTP security issue flagging)

#### Phase 1: TLS Metadata (v0.9.4-0.9.5)
- **v0.9.4**: TLS metadata extraction (protocol version, cipher suite, OCSP responder detection, IPv6 support)
- **v0.9.5**: OCSP revocation status checking (practical implementation with certificate validity inference)

#### Phase 2: High-Value Features (v1.0.0 - Already Implemented)
- Domain registration information via RDAP API (WHOIS replacement)
- HTTP security headers audit (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- Subdomain enumeration (DNS resolution + HTTP status + TLS validity)
- Port reachability testing (TCP connectivity + service detection)

### MCP Tools (26 Total)

**Core tools**: check_dns, check_http, check_tls_chain, check_email_security, check_mta_sts, check_ocsp, check_starttls, check_domain_health, check_caa, check_bimi, check_ct, check_propagation_global, check_propagation, check_dnssec, check_whois

**Tier 2 additions**: check_subdomains, check_ports, check_rdns, check_dnsbl, detect_cdn, check_delegation

### Changes

- Improved email security scoring with proportional DKIM points
- Enhanced STARTTLS protocol handling with proper response parsing
- DMARC validation now correctly rejects p=none policies
- SPF/DMARC issues array populated with actionable linting results
- OCSP responder URL detection from AIA extension

### Dependencies

- Added `ocsp` crate (0.3) for OCSP response structures
- All dependencies up to date with MSRV 1.85

---

## Roadmap

### v1.1 (Planned)

- CT (Certificate Transparency) SCT parsing + crt.sh API integration
- STARTTLS TLS upgrade execution (actual TLS handshake post-STARTTLS)
- Full OCSP request/response ASN.1 encoding
- Email delivery simulation (MTA-STS policy, SMTP relay testing)

### v2.0 (Future)

- Web UI + WebSocket dashboard
- Bulk health checking + CSV import/export
- Scheduled monitoring + alerting
