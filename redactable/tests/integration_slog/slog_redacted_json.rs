use super::*;

#[derive(Clone, Serialize)]
struct NoDebugEvent {
    public: String,
    secret: String,
}

impl RedactableWithMapper for NoDebugEvent {
    fn redact_with<M: RedactableMapper>(mut self, mapper: &M) -> Self {
        self.secret = mapper.map_sensitive::<_, Secret>(self.secret);
        self
    }
}

impl Redactable for NoDebugEvent {}

#[test]
fn slog_redacted_json_does_not_require_debug() {
    const CANARY: &str = "phase02b-no-debug-canary-7391";
    fn assert_extension<T: SlogRedactedExt>() {}
    assert_extension::<NoDebugEvent>();

    let redacted = NoDebugEvent {
        public: "visible".to_owned(),
        secret: CANARY.to_owned(),
    }
    .slog_redacted_json();

    let expected = serde_json::json!({
        "public": "visible",
        "secret": "[REDACTED]",
    });
    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&redacted, "event", &mut serializer);
    assert_eq!(
        serializer.get("event"),
        Some(CapturedValue::Serde(expected))
    );
    assert!(!format!("{:?}", serializer.get("event")).contains(CANARY));
}

#[path = "slog_redacted_json/basic.rs"]
mod basic;
#[path = "slog_redacted_json/containers.rs"]
mod containers;
#[path = "slog_redacted_json/custom_policy.rs"]
mod custom_policy;
#[path = "slog_redacted_json/edge_cases.rs"]
mod edge_cases;
#[path = "slog_redacted_json/enums.rs"]
mod enums;
#[path = "slog_redacted_json/nested.rs"]
mod nested;
#[path = "slog_redacted_json/security.rs"]
mod security;
