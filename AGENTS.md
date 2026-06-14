shohei — Rust MCP security server + library

@tasks/todo.md
@tasks/lessons.md
@README.md
@CHANGELOG.md

## What is shohei

A **Rust library** (`use shohei;`) and **MCP server** (`shohei-mcp`) providing 168 security diagnostic tools across 66 modules. AI agents (Claude, etc.) connect via MCP and call tools to inspect DNS, TLS, email security, HTTP, cloud infrastructure, OSINT, threat intelligence, and more — no API keys required.

**Primary consumers, in priority order:**
1. AI agents via MCP (Claude Desktop, Claude Code)
2. Rust library users — `use shohei::api::*`
3. CI/CD pipelines — `shohei-mcp` as a subprocess
4. CLI users — `shohei` binary (thin demo wrapper)

## Repository layout

```
src/
  api/          — 66 modules, one concern each
    helpers.rs  — shared utilities (MUST read before adding network code)
    mod.rs      — re-exports all modules; add new modules here
    *.rs        — individual feature modules
  bin/
    shohei_mcp.rs  — MCP server; 168 tool handlers (one Params struct + one #[tool] fn per tool)
  resolver/
    mod.rs, standard.rs, iterative.rs  — hickory-dns resolver wrappers
    zone_transfer.rs                   — AXFR logic
  error.rs      — ShoheError enum + Result<T> alias
  lib.rs        — crate root
tasks/          — project management (not compiled)
```

## Module pattern

Every module follows the same shape:

```rust
// src/api/example.rs

use serde::{Deserialize, Serialize};
use crate::error::Result;
use crate::api::helpers::{validate_url_safety, build_http_client};

#[derive(Debug, Deserialize, Default)]
pub struct ExampleRequest {
    pub domain: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}
fn default_timeout() -> u64 { 10 }

#[derive(Debug, Serialize)]
pub struct ExampleResult {
    pub domain: String,
    pub findings: Vec<String>,
    pub checked_at: String,
}

pub async fn check_example(req: &ExampleRequest) -> Result<ExampleResult> {
    validate_url_safety(&format!("https://{}", req.domain))
        .map_err(|e| crate::error::ShoheError::Parse(e))?;
    let client = build_http_client(req.timeout_secs)?;
    // ...
    Ok(ExampleResult { domain: req.domain.clone(), findings: vec![], checked_at: helpers::now_rfc3339() })
}
```

## Adding a new tool — checklist

1. **Create** `src/api/<name>.rs` following the module pattern above
2. **Register** in `src/api/mod.rs`:
   ```rust
   pub mod name;
   pub use name::{check_name, NameRequest, NameResult};
   ```
3. **Add MCP handler** in `src/bin/shohei_mcp.rs`:
   ```rust
   #[derive(Deserialize, schemars::JsonSchema, Clone)]
   struct CheckNameParams {
       /// Doc comment shown to AI as tool description
       domain: String,
   }

   #[tool(description = "One-line description for the AI")]
   async fn check_name(&self, Parameters(p): Parameters<CheckNameParams>) -> String {
       api_result(shohei::api::check_name(&NameRequest {
           domain: p.domain,
           ..Default::default()
       }).await)
   }
   ```
4. **Verify**: `cargo build --bin shohei-mcp`
5. **Test**: `cargo test --lib`

## Shared helpers (`src/api/helpers.rs`)

Always prefer these over rolling your own:

| Helper | Use when |
|--------|----------|
| `validate_url_safety(url)` | **Before any HTTP/TCP call where host comes from user input.** Blocks SSRF: loopback, RFC1918, link-local, `file://`, alt IPv4 forms. Returns `Err(String)` on violation. |
| `build_http_client(timeout_secs)` | Building a `reqwest::Client`. Sets timeout, user-agent, and safe defaults. Never use `Client::new()`. |
| `resolve_hostname_to_ip(host, timeout)` | DNS resolution to `IpAddr`. Falls back to system resolver. |
| `resolve_first_cname(domain, timeout)` | CNAME lookup — avoids repeating the same 3-step block across modules. |
| `now_timestamp()` | Current UNIX time as `u64`. Use instead of `SystemTime` (avoids non-determinism in tests). |
| `now_rfc3339()` | RFC 3339 timestamp string for `checked_at` fields. |
| `hex_encode(data)` | Faster than `format!("{:02x}", b)` loop — uses lookup table. |
| `percent_encode(s)` | URL-encodes a string (no external dep). |
| `generate_id(prefix)` | Deterministic ID from timestamp — use for trace/correlation IDs. |

## Security requirements (non-negotiable)

### SSRF prevention
Any function that makes an HTTP or TCP connection to a host derived from user input **must** call `validate_url_safety` first:
```rust
validate_url_safety(&format!("https://{}", req.domain))
    .map_err(|e| ShoheError::Parse(e))?;
```
Validate the **initial** URL and also each **redirect hop**. Use `Policy::custom` for redirect-following clients:
```rust
let client = reqwest::Client::builder()
    .redirect(reqwest::redirect::Policy::custom(|attempt| {
        let url = attempt.url().as_str();
        if validate_url_safety(url).is_err() { attempt.stop() } else { attempt.follow() }
    }))
    .timeout(std::time::Duration::from_secs(req.timeout_secs))
    .build()?;
```
Protocols that must NOT follow redirects: MTA-STS fetch (RFC 8461 §3.3), DKIM key fetch, zone transfer.

### JSON output
Never use `format!()` to build JSON with user-controlled data — use `serde_json::json!`:
```rust
// BAD
format!("{{\"error\": \"{}\"}}", user_msg)
// GOOD
serde_json::json!({"error": user_msg}).to_string()
```
`api_result<T>` in `shohei_mcp.rs` already handles this for tool error paths.

### Integer arithmetic
Use `saturating_*` for all arithmetic on u8/u16/u32 that could under/overflow in security-relevant paths (scores, counts, limits). Never subtract unsigned integers without saturating or checked arithmetic.

### Resource caps
- Loop reading from network: add a message/iteration cap (`MAX_ITERATIONS = N`)
- `tokio::spawn` fan-out: cap at a sensible bound (e.g. `take(50)`) before spawning

### String slicing
Never slice Rust strings by byte index when the index was computed by iterating chars. Use `.chars().enumerate()` + `.char_indices()`, or collect to `Vec<char>` first.

## Error handling

```rust
// src/error.rs
pub enum ShoheError {
    DnsResolution(String),
    DnsProto(hickory_proto::ProtoError),
    DnssecValidation(String),
    Transport(String),
    Parse(String),
    Io(std::io::Error),
}
pub type Result<T> = std::result::Result<T, ShoheError>;
```

Use `ShoheError::Parse(msg)` for input validation failures, `Transport(msg)` for network errors, `DnsResolution(msg)` for DNS failures. Do not add new error variants unless none of the existing ones fit.

## Async patterns

Prefer parallel execution for independent I/O:
```rust
// sequential — avoid for independent calls
let a = call_a().await?;
let b = call_b().await?;

// parallel — prefer
let (a, b) = tokio::join!(call_a(), call_b());

// parallel fan-out over a list
let handles: Vec<_> = items.iter().map(|item| tokio::spawn(work(item.clone()))).collect();
let results: Vec<_> = futures::future::join_all(handles).await;
```

## Build & test

```bash
# Verify the MCP binary compiles (most common check)
cargo build --bin shohei-mcp

# Run unit tests (no network)
cargo test --lib

# Run a specific module's tests
cargo test --lib api::dnsbl

# Network-dependent tests (requires internet)
cargo test -- --include-ignored

# Release build for performance testing
cargo build --release --bin shohei-mcp
```

## MCP tool handler pattern (`src/bin/shohei_mcp.rs`)

```rust
// api_result handles both Ok and Err paths safely
fn api_result<T: serde::Serialize>(r: shohei::error::Result<T>) -> String {
    match r {
        Ok(v) => serde_json::to_string_pretty(&v).unwrap_or_default(),
        Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
    }
}
```

Tool descriptions (the `description = "..."` on `#[tool]`) are read by Claude. Write them as actions: `"Check X for Y"`, not `"Returns X"`. Include what fields matter in the Params struct doc comments.

## Module groups (for navigation)

| Group | Modules |
|-------|---------|
| DNS / Network | `propagation`, `delegation`, `dnsbl`, `dns_amplification`, `dns_hijacking`, `wildcard_dns`, `rdns`, `bgp_route`, `ipv6`, `zone_transfer` |
| TLS / Crypto | `tls`, `tlsvuln`, `cipher_suites`, `crypto`, `ct`, `ocsp`, `bimi`, `rpki` |
| Email | `email`, `email_advanced`, `mta_sts`, `tls_rpt`, `spf_analysis`, `arc`, `starttls` |
| HTTP / Web | `http`, `redirect_chain`, `url_intel`, `url_analysis`, `urlhaus`, `web_intelligence`, `cdn` |
| Identity / Auth | `identity_security`, `governance`, `trust_scoring`, `compliance` |
| Cloud / Infra | `cloud_exposure`, `cloud_security`, `supply_chain`, `service_exposure`, `ports` |
| OSINT / Threat | `osint`, `threat_intelligence`, `domain_risk`, `brand_impersonation`, `typosquat`, `dga_and_threat`, `subdomain_takeover_ext` |
| Misc | `helpers`, `health`, `bench`, `traceroute`, `ssh_fingerprint`, `techfingerprint`, `whois`, `ipinfo`, `greynoise`, `shodan_internetdb`, `parked_domain`, `network_reputation`, `privacy`, `subdomain`, `caa`, `cve_lookup`, `username_osint` |

## Design principles

- **Library first**: every feature is a public `async fn` in `src/api/`. The MCP binary and CLI binary are thin wrappers.
- **Zero API keys**: all 168 tools use public APIs or direct network probing. Do not add tools requiring paid API keys without a free tier fallback.
- **Structured output**: all results are `Serialize`. No colored or human-formatted strings in the library layer.
- **Composable**: tools can call other tools (e.g. `compliance.rs` calls `tls`, `http`, `email`). Import from `crate::api::*`.
- **No panics on user input**: every code path reachable from user-supplied data must handle errors gracefully. `unwrap()` is only acceptable on infallible operations (e.g. compiling a static regex).
