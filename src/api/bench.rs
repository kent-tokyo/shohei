//! Multi-protocol latency benchmarking.

use serde::{Deserialize, Serialize};
use crate::error::Result;
use crate::api::{check_dns, DnsCheckRequest, Transport};

/// Benchmark DNS query latency across multiple transports.
pub async fn benchmark_latency(req: &LatencyBenchRequest) -> Result<LatencyBenchResult> {
    let mut results = Vec::new();

    for bench_transport in &req.transports {
        let mut samples_ms = Vec::new();

        for _ in 0..req.rounds {
            let dns_req = DnsCheckRequest {
                domain: req.domain.clone(),
                record_types: vec![req.record_type.clone()],
                transport: bench_transport.transport.clone(),
                timeout_secs: req.timeout_secs,
                ..Default::default()
            };

            let sample = match check_dns(&dns_req).await {
                Ok(results) if !results.is_empty() => Some(results[0].duration_ms),
                _ => None,
            };
            samples_ms.push(sample);
        }

        let valid_samples: Vec<u64> = samples_ms.iter().filter_map(|s| *s).collect();
        let success_rate = if req.rounds > 0 {
            valid_samples.len() as f64 / req.rounds as f64
        } else {
            0.0
        };

        let (min_ms, max_ms, avg_ms, stddev_ms, p95_ms, p99_ms) = if !valid_samples.is_empty() {
            let min = *valid_samples.iter().min().unwrap_or(&0);
            let max = *valid_samples.iter().max().unwrap_or(&0);
            let avg = valid_samples.iter().sum::<u64>() as f64 / valid_samples.len() as f64;

            // Calculate stddev
            let variance = valid_samples.iter()
                .map(|x| {
                    let diff = *x as f64 - avg;
                    diff * diff
                })
                .sum::<f64>() / valid_samples.len() as f64;
            let stddev = variance.sqrt();

            // Calculate percentiles
            let mut sorted = valid_samples.clone();
            sorted.sort_unstable();
            let p95_idx = ((sorted.len() as f64 * 0.95).ceil() as usize).min(sorted.len() - 1);
            let p99_idx = ((sorted.len() as f64 * 0.99).ceil() as usize).min(sorted.len() - 1);
            let p95 = sorted.get(p95_idx).copied();
            let p99 = sorted.get(p99_idx).copied();

            (Some(min), Some(max), Some(avg), Some(stddev), p95, p99)
        } else {
            (None, None, None, None, None, None)
        };

        results.push(TransportLatency {
            label: bench_transport.label.clone(),
            transport: bench_transport.transport.clone(),
            samples_ms,
            min_ms,
            max_ms,
            avg_ms,
            stddev_ms,
            p95_ms,
            p99_ms,
            success_rate,
        });
    }

    Ok(LatencyBenchResult {
        domain: req.domain.clone(),
        record_type: req.record_type.clone(),
        results,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyBenchRequest {
    pub domain: String,
    pub record_type: String,
    pub transports: Vec<BenchTransport>,
    #[serde(default = "default_rounds")]
    pub rounds: u32,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_rounds() -> u32 { 3 }
fn default_timeout() -> u64 { 5 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchTransport {
    pub transport: Transport,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyBenchResult {
    pub domain: String,
    pub record_type: String,
    pub results: Vec<TransportLatency>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportLatency {
    pub label: String,
    pub transport: Transport,
    pub samples_ms: Vec<Option<u64>>,
    pub min_ms: Option<u64>,
    pub max_ms: Option<u64>,
    pub avg_ms: Option<f64>,
    pub stddev_ms: Option<f64>,  // NEW: standard deviation
    pub p95_ms: Option<u64>,      // NEW: 95th percentile
    pub p99_ms: Option<u64>,      // NEW: 99th percentile
    pub success_rate: f64,
}
