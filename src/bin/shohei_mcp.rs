//! shohei MCP server — expose shohei library API as Claude tools.
//!
//! This binary makes shohei's DNS/TLS/email/propagation/latency APIs available
//! to Claude and other AI agents via the Model Context Protocol (MCP).
//!
//! Run with: shohei-mcp (reads JSON-RPC 2.0 on stdin, writes on stdout)

use serde_json::{json, Value};
use shohei::api::*;
use std::io::{BufRead, Write};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let reader = stdin.lock();
    let mut lines = reader.lines();

    // List of available tools
    let tools = vec![
        json!({
            "name": "check_dns",
            "description": "Check DNS records for a domain",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "domain": { "type": "string", "description": "Domain to query" },
                    "record_types": { "type": "array", "items": { "type": "string" }, "description": "Record types (A, AAAA, MX, TXT, etc)" }
                },
                "required": ["domain"]
            }
        }),
        json!({
            "name": "check_tls_chain",
            "description": "Inspect TLS certificate chain for a hostname",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "hostname": { "type": "string", "description": "Hostname to inspect" },
                    "port": { "type": "number", "description": "Port (default 443)" },
                    "check_dane": { "type": "boolean", "description": "Check DANE/TLSA records" }
                },
                "required": ["hostname"]
            }
        }),
        json!({
            "name": "check_email_security",
            "description": "Check email security (MX, SPF, DKIM, DMARC)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "domain": { "type": "string", "description": "Domain to check" }
                },
                "required": ["domain"]
            }
        }),
        json!({
            "name": "check_propagation_global",
            "description": "Check DNS propagation across 6 global resolvers",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "domain": { "type": "string", "description": "Domain to check" }
                },
                "required": ["domain"]
            }
        }),
        json!({
            "name": "benchmark_latency",
            "description": "Benchmark DNS latency across transports",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "domain": { "type": "string", "description": "Domain to benchmark" },
                    "transports": { "type": "array", "items": { "type": "string" }, "description": "Transports to test" }
                },
                "required": ["domain"]
            }
        }),
    ];

    // Main loop
    while let Some(Ok(line)) = lines.next() {
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let id = req.get("id").cloned();
        let method = req.get("method").and_then(|m| m.as_str());
        let params = req.get("params").cloned().unwrap_or(Value::Object(Default::default()));

        let result = match method {
            Some("tools/list") => {
                json!({
                    "tools": tools
                })
            }
            Some("tools/call") => {
                let tool_name = params.get("name").and_then(|n| n.as_str());
                let arguments = params.get("arguments").cloned().unwrap_or(Value::Object(Default::default()));

                match tool_name {
                    Some("check_dns") => {
                        if let (Some(domain), record_types) = (
                            arguments.get("domain").and_then(|d| d.as_str()),
                            arguments.get("record_types").and_then(|rt| rt.as_array()).map(|arr| {
                                arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()
                            }).unwrap_or_else(|| vec!["A".to_string()])
                        ) {
                            let req = DnsCheckRequest {
                                domain: domain.to_string(),
                                record_types,
                                ..Default::default()
                            };
                            match shohei::api::check_dns(&req).await {
                                Ok(results) => json!({"content": [{"type": "text", "text": format!("{:?}", results)}]}),
                                Err(e) => json!({"content": [{"type": "text", "text": format!("Error: {}", e)}]})
                            }
                        } else {
                            json!({"content": [{"type": "text", "text": "Missing domain parameter"}]})
                        }
                    }
                    Some("check_tls_chain") => {
                        if let Some(hostname) = arguments.get("hostname").and_then(|h| h.as_str()) {
                            let port = arguments.get("port").and_then(|p| p.as_u64()).unwrap_or(443) as u16;
                            let check_dane = arguments.get("check_dane").and_then(|cd| cd.as_bool()).unwrap_or(false);
                            let req = TlsCheckRequest {
                                hostname: hostname.to_string(),
                                port,
                                check_dane,
                                timeout_secs: 10,
                            };
                            match shohei::api::check_tls_chain(&req).await {
                                Ok(result) => json!({"content": [{"type": "text", "text": format!("{:?}", result)}]}),
                                Err(e) => json!({"content": [{"type": "text", "text": format!("Error: {}", e)}]})
                            }
                        } else {
                            json!({"content": [{"type": "text", "text": "Missing hostname parameter"}]})
                        }
                    }
                    Some("check_email_security") => {
                        if let Some(domain) = arguments.get("domain").and_then(|d| d.as_str()) {
                            let req = EmailSecurityRequest {
                                domain: domain.to_string(),
                                timeout_secs: 5,
                                dkim_selectors: vec![
                                    "default".to_string(),
                                    "google".to_string(),
                                    "selector1".to_string(),
                                    "selector2".to_string(),
                                ],
                            };
                            match shohei::api::check_email_security(&req).await {
                                Ok(result) => json!({"content": [{"type": "text", "text": format!("Score: {}/100, MX: {}, SPF: {}, DMARC: {}, DKIM: {}", result.score, result.mx.valid, result.spf.valid, result.dmarc.valid, result.dkim.iter().filter(|d| d.present).count())}]}),
                                Err(e) => json!({"content": [{"type": "text", "text": format!("Error: {}", e)}]})
                            }
                        } else {
                            json!({"content": [{"type": "text", "text": "Missing domain parameter"}]})
                        }
                    }
                    Some("check_propagation_global") => {
                        if let Some(domain) = arguments.get("domain").and_then(|d| d.as_str()) {
                            match shohei::api::check_propagation_global(domain).await {
                                Ok(result) => json!({"content": [{"type": "text", "text": format!("Propagation check: consistent={}, resolvers={}", result.consistent, result.results.len())}]}),
                                Err(e) => json!({"content": [{"type": "text", "text": format!("Error: {}", e)}]})
                            }
                        } else {
                            json!({"content": [{"type": "text", "text": "Missing domain parameter"}]})
                        }
                    }
                    Some("benchmark_latency") => {
                        if let Some(domain) = arguments.get("domain").and_then(|d| d.as_str()) {
                            let req = LatencyBenchRequest {
                                domain: domain.to_string(),
                                record_type: "A".to_string(),
                                transports: vec![
                                    BenchTransport { transport: Transport::System, label: "System".to_string() },
                                    BenchTransport { transport: Transport::Doh("https://1.1.1.1/dns-query".to_string()), label: "DoH-Cloudflare".to_string() },
                                ],
                                rounds: 3,
                                timeout_secs: 5,
                            };
                            match shohei::api::benchmark_latency(&req).await {
                                Ok(result) => json!({"content": [{"type": "text", "text": format!("{:?}", result)}]}),
                                Err(e) => json!({"content": [{"type": "text", "text": format!("Error: {}", e)}]})
                            }
                        } else {
                            json!({"content": [{"type": "text", "text": "Missing domain parameter"}]})
                        }
                    }
                    _ => json!({"content": [{"type": "text", "text": "Unknown tool"}]})
                }
            }
            _ => json!({"error": {"code": -32601, "message": "Method not found"}}),
        };

        let response = json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result
        });

        writeln!(stdout, "{}", response.to_string())?;
        stdout.flush()?;
    }

    Ok(())
}
