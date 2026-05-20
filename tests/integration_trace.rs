use hickory_proto::rr::RecordType;
use shohei::resolver::iterative::{StepResponseType, trace};

#[tokio::test]
#[ignore = "requires network"]
async fn test_trace_has_steps() {
    let result = trace("example.com", RecordType::A, None)
        .await
        .expect("trace failed");

    assert!(!result.steps.is_empty(), "expected at least one trace step");
    assert_eq!(result.target, "example.com");
}

#[tokio::test]
#[ignore = "requires network"]
async fn test_trace_ends_with_answer() {
    let result = trace("example.com", RecordType::A, None)
        .await
        .expect("trace failed");

    let last = result.steps.last().expect("no steps");
    assert!(
        matches!(last.response_type, StepResponseType::Answer),
        "expected final step to be an answer, got {:?}",
        last.response_type
    );
}

#[tokio::test]
#[ignore = "requires network"]
async fn test_trace_starts_with_root_referral() {
    let result = trace("google.com", RecordType::A, None)
        .await
        .expect("trace failed");

    let first = result.steps.first().expect("no steps");
    assert!(
        first.server_name.contains("root-servers.net"),
        "first step should be a root server, got {}",
        first.server_name
    );
    assert!(
        matches!(first.response_type, StepResponseType::Referral),
        "root server should return a referral"
    );
}

#[tokio::test]
#[ignore = "requires network"]
async fn test_trace_has_at_least_three_steps() {
    // root → TLD → authoritative
    let result = trace("example.com", RecordType::A, None)
        .await
        .expect("trace failed");

    assert!(
        result.steps.len() >= 3,
        "expected at least 3 hops (root → TLD → authoritative), got {}",
        result.steps.len()
    );
}

#[tokio::test]
#[ignore = "requires network"]
async fn test_trace_referrals_have_referral_names() {
    let result = trace("example.com", RecordType::A, None)
        .await
        .expect("trace failed");

    for step in &result.steps {
        if matches!(step.response_type, StepResponseType::Referral) {
            assert!(
                step.referral_to.as_ref().map(|v| !v.is_empty()).unwrap_or(false),
                "referral step should list referred nameservers"
            );
        }
    }
}

#[tokio::test]
#[ignore = "requires network"]
async fn test_trace_nxdomain() {
    let result = trace("this-domain-definitely-does-not-exist-xyz123.com", RecordType::A, None)
        .await
        .expect("trace should not error on NXDOMAIN");

    let last = result.steps.last().expect("no steps");
    assert!(
        matches!(
            last.response_type,
            StepResponseType::Nxdomain | StepResponseType::Error(_)
        ),
        "nonexistent domain should end with Nxdomain or Error"
    );
}
