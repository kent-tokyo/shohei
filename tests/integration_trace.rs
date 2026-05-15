use hickory_proto::rr::RecordType;
use shohei::resolver::iterative::{trace, StepResponseType};

#[tokio::test]
async fn test_trace_has_steps() {
    let result = trace("example.com", RecordType::A)
        .await
        .expect("trace failed");

    assert!(!result.steps.is_empty(), "expected at least one trace step");
    assert_eq!(result.target, "example.com");
}

#[tokio::test]
async fn test_trace_ends_with_answer() {
    let result = trace("example.com", RecordType::A)
        .await
        .expect("trace failed");

    let last = result.steps.last().expect("no steps");
    assert!(
        matches!(last.response_type, StepResponseType::Answer),
        "expected final step to be an answer, got {:?}",
        last.response_type
    );
}
