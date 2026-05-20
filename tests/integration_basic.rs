use hickory_proto::rr::RecordType;
use shohei::resolver::{standard, QueryOptions, RecordData};

#[tokio::test]
async fn test_query_a_record() {
    let opts = QueryOptions {
        domain: "example.com".to_string(),
        record_type: RecordType::A,
        server: Some("8.8.8.8:53".parse().unwrap()),
        transport: None,
        validate_dnssec: false,
        force_tcp: false,
        no_recurse: false,
        timeout_secs: 5,
    };

    let result = standard::query(&opts).await.expect("query failed");
    assert!(!result.answers.is_empty(), "expected at least one A record");
    for record in &result.answers {
        assert!(
            matches!(record.data, RecordData::A(_)),
            "expected A record data"
        );
    }
}

#[tokio::test]
async fn test_query_mx_record() {
    let opts = QueryOptions {
        domain: "gmail.com".to_string(),
        record_type: RecordType::MX,
        server: Some("8.8.8.8:53".parse().unwrap()),
        transport: None,
        validate_dnssec: false,
        force_tcp: false,
        no_recurse: false,
        timeout_secs: 5,
    };

    let result = standard::query(&opts).await.expect("query failed");
    assert!(
        !result.answers.is_empty(),
        "expected at least one MX record"
    );
}

#[tokio::test]
async fn test_query_txt_record() {
    let opts = QueryOptions {
        domain: "example.com".to_string(),
        record_type: RecordType::TXT,
        server: Some("8.8.8.8:53".parse().unwrap()),
        transport: None,
        validate_dnssec: false,
        force_tcp: false,
        no_recurse: false,
        timeout_secs: 5,
    };

    let result = standard::query(&opts).await.expect("query failed");
    // TXT records may or may not exist; just ensure it doesn't error
    assert!(result.duration_ms > 0);
}
