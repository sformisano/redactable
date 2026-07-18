use super::*;

#[test]
fn emits_structured_json() {
    #[derive(Serialize)]
    struct Metadata {
        id: u64,
        label: String,
    }

    let value = Metadata {
        id: 42,
        label: "ok".into(),
    };

    let wrapped = value.not_sensitive_json();
    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&wrapped, "meta", &mut serializer);

    if let Some(CapturedValue::Serde(json)) = serializer.get("meta") {
        assert_eq!(json["id"], 42);
        assert_eq!(json["label"], "ok");
    } else {
        panic!("Expected Serde value for 'meta' key");
    }
}

#[test]
fn works_with_to_redacted_output() {
    #[derive(Serialize)]
    struct Metadata {
        id: u64,
        label: String,
    }

    let value = Metadata {
        id: 99,
        label: "ok".into(),
    };

    let output = log_redacted(&value.not_sensitive_json());
    if let RedactedOutput::Json(json) = output {
        assert_eq!(json["id"], 99);
        assert_eq!(json["label"], "ok");
    } else {
        panic!("Expected Json output");
    }
}
