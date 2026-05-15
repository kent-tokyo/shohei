use hickory_proto::rr::RecordType;
use shohei::dnssec::build_chain;
use shohei::resolver::TrustState;

#[tokio::test]
async fn test_dnssec_chain_signed_domain() {
    // cloudflare.com is DNSSEC-signed
    let chain = build_chain("cloudflare.com", RecordType::A)
        .await
        .expect("chain build failed");

    assert_eq!(chain.domain, "cloudflare.com");
    assert!(!chain.steps.is_empty(), "expected at least one DNSSEC step");
}

#[tokio::test]
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
