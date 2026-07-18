use super::*;

#[test]
fn redacts_before_serialization() {
    #[derive(Clone, Sensitive, Serialize)]
    struct Canary {
        #[sensitive(Secret)]
        secret: String,
    }

    let canary = Canary {
        secret: "the_actual_secret".into(),
    };

    let redacted = canary.slog_redacted_json();
    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&redacted, "canary", &mut serializer);

    if let Some(CapturedValue::Serde(json)) = serializer.get("canary") {
        assert_eq!(json["secret"], "[REDACTED]");
    } else {
        panic!("Expected Serde value for 'canary' key");
    }
}
