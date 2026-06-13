use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::op::update_message::zone_transfer as build_axfr_query;
use hickory_proto::rr::{Name, RData};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{Result, ShoheError};
use crate::resolver::{DnsQuery, DnsQueryResult, DnsRecord};
use crate::resolver::standard::record_to_dns_record;

/// Caps for resource exhaustion protection (S2)
const MAX_ZONE_RECORDS: usize = 500_000;

/// Monotonically incrementing counter for query IDs (S4)
static QUERY_ID_CTR: AtomicU16 = AtomicU16::new(1);

/// Perform an AXFR (full zone transfer) over a dedicated TCP connection.
/// Bypasses hickory's multiplexer, which is incompatible with AXFR's multi-message stream.
pub async fn axfr(domain: &str, server: SocketAddr, timeout_secs: u64) -> Result<DnsQueryResult> {
    let timeout = Duration::from_secs(timeout_secs);

    let name: Name = domain
        .parse()
        .map_err(|e| ShoheError::Parse(format!("invalid domain '{domain}': {e}")))?;

    // Establish dedicated TCP connection for AXFR (not shared with multiplexer)
    let mut tcp = tokio::time::timeout(timeout, TcpStream::connect(server))
        .await
        .map_err(|_| ShoheError::Transport(format!("connection to {server} timed out")))?
        .map_err(|e| ShoheError::Io(e))?;

    // Build and send AXFR query with a non-fixed transaction ID (S4)
    let query_id = QUERY_ID_CTR.fetch_add(1, Ordering::Relaxed);
    let mut query = build_axfr_query(name.clone(), None);
    query.metadata.id = query_id;
    let query_bytes = query
        .to_vec()
        .map_err(|e| ShoheError::DnsProto(e))?;
    let msg_len = u16::try_from(query_bytes.len())
        .map_err(|_| ShoheError::Transport("AXFR query too large".to_string()))?;

    // DNS-over-TCP: 2-byte big-endian length prefix, then message bytes
    let mut frame = Vec::with_capacity(2 + query_bytes.len());
    frame.extend_from_slice(&msg_len.to_be_bytes());
    frame.extend_from_slice(&query_bytes);
    tcp.write_all(&frame).await?;

    // Receive zone data: read DNS messages until final SOA is seen
    let mut records: Vec<DnsRecord> = Vec::new();
    let mut expected_serial: Option<u32> = None;
    let start = std::time::Instant::now();
    let mut message_count = 0usize;
    const MAX_AXFR_MESSAGES: usize = 10_000;

    loop {
        message_count += 1;
        if message_count > MAX_AXFR_MESSAGES {
            return Err(ShoheError::Transport(format!(
                "AXFR from {server} exceeded {MAX_AXFR_MESSAGES} message limit"
            )));
        }
        if start.elapsed() >= timeout {
            return Err(ShoheError::Transport(format!("AXFR from {server} timed out")));
        }
        let remaining = timeout.saturating_sub(start.elapsed());

        // Read 2-byte length prefix
        let mut len_buf = [0u8; 2];
        tokio::time::timeout(remaining, tcp.read_exact(&mut len_buf))
            .await
            .map_err(|_| ShoheError::Transport(format!("AXFR read from {server} timed out")))?
            .map_err(|e| ShoheError::Io(e))?;

        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 {
            break;
        }

        // Read message bytes
        let mut msg_buf = vec![0u8; msg_len];
        let remaining = timeout.saturating_sub(start.elapsed());
        tokio::time::timeout(remaining, tcp.read_exact(&mut msg_buf))
            .await
            .map_err(|_| ShoheError::Transport(format!("AXFR read from {server} timed out")))?
            .map_err(|e| ShoheError::Io(e))?;

        let message = Message::from_vec(&msg_buf)
            .map_err(|e| ShoheError::DnsProto(e.into()))?;

        // Check RCODE — surface REFUSED/SERVFAIL immediately (B1)
        let rcode = message.response_code;
        if rcode != ResponseCode::NoError {
            return Err(ShoheError::DnsResolution(format!(
                "AXFR from {server} returned error: {rcode}"
            )));
        }

        // Verify transaction ID matches (S4)
        if message.metadata.id != query_id {
            eprintln!(
                "warning: AXFR response with mismatched ID {} (expected {})",
                message.metadata.id, query_id
            );
            continue;
        }

        // Collect records and track SOA serial for AXFR termination (RFC 5936)
        let mut done = false;
        for record in &message.answers {
            // Resource exhaustion guard (S2)
            if records.len() >= MAX_ZONE_RECORDS {
                return Err(ShoheError::DnsResolution(format!(
                    "AXFR from {server} exceeded {MAX_ZONE_RECORDS} record limit"
                )));
            }

            if let RData::SOA(soa) = &record.data {
                match expected_serial {
                    None => {
                        // First SOA: save serial, marks start of zone
                        expected_serial = Some(soa.serial);
                        records.push(record_to_dns_record(record));
                    }
                    Some(serial) if soa.serial == serial => {
                        // Final SOA matches start SOA: zone transfer complete (RFC 5936)
                        records.push(record_to_dns_record(record));
                        done = true;
                        break;
                    }
                    _ => {
                        records.push(record_to_dns_record(record));
                    }
                }
            } else {
                records.push(record_to_dns_record(record));
            }
        }

        if done {
            break;
        }
        // No early-exit on empty-answer messages — rely solely on closing SOA (B2/S5)
    }

    if records.is_empty() {
        return Err(ShoheError::DnsResolution(format!(
            "AXFR from {server} returned no records"
        )));
    }

    Ok(DnsQueryResult {
        query: DnsQuery {
            name: domain.to_string(),
            record_type: "AXFR".to_string(),
            class: "IN".to_string(),
        },
        answers: records,
        authority: vec![],
        additional: vec![],
        duration_ms: start.elapsed().as_millis() as u64,
        server_addr: server.to_string(),
    })
}
