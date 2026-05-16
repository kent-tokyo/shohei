use hickory_proto::rr::RecordType;
use shohei::dnssec::build_chain;
use shohei::resolver::TrustState;

#[tokio::test]
#[ignore = "requires network"]
async fn test_dnssec_signed_domain_is_secure() {
    // cloudflare.com is DNSSEC-signed
    let chain = build_chain("cloudflare.com", RecordType::A)
        .await
        .expect("chain build failed");

    assert_eq!(chain.overall, TrustState::Secure, "cloudflare.com should be SECURE");
}

#[tokio::test]
#[ignore = "requires network"]
async fn test_dnssec_unsigned_domain_is_insecure() {
    // google.com is NOT DNSSEC-signed
    let chain = build_chain("google.com", RecordType::A)
        .await
        .expect("chain build failed");

    assert_eq!(chain.overall, TrustState::Insecure, "google.com should be INSECURE (unsigned)");
}

#[tokio::test]
#[ignore = "requires network"]
async fn test_dnssec_chain_has_trust_anchor() {
    use shohei::dnssec::chain::DnssecStepType;

    let chain = build_chain("cloudflare.com", RecordType::A)
        .await
        .expect("chain build failed");

    let has_anchor = chain
        .steps
        .iter()
        .any(|s| matches!(s.step_type, DnssecStepType::TrustAnchor));
    assert!(has_anchor, "expected a trust anchor step");
}

#[tokio::test]
#[ignore = "requires network"]
async fn test_dnssec_chain_ends_with_answer() {
    use shohei::dnssec::chain::DnssecStepType;

    let chain = build_chain("example.com", RecordType::A)
        .await
        .expect("chain build failed");

    let last = chain.steps.last().expect("no steps");
    assert!(
        matches!(last.step_type, DnssecStepType::Answer),
        "last step should be Answer"
    );
}

#[tokio::test]
#[ignore = "requires network"]
async fn test_dnssec_example_com_is_secure() {
    // example.com is DNSSEC-signed
    let chain = build_chain("example.com", RecordType::A)
        .await
        .expect("chain build failed");

    assert_eq!(chain.overall, TrustState::Secure, "example.com should be SECURE");
}
