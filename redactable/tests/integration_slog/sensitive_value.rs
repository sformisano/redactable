use crate::slog_capture::{CapturedValue, CapturingSerializer, serialize_to_capture};
use redactable::{Secret, SensitiveValue};

#[test]
fn slog_serialization_emits_redacted_value() {
    let token = SensitiveValue::<String, Secret>::from(String::from("sk-secret-12345"));

    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&token, "token", &mut serializer);

    if let Some(CapturedValue::Str(value)) = serializer.get("token") {
        assert_eq!(value, "[REDACTED]");
    } else {
        panic!("Expected Str value for 'token' key");
    }
    assert_eq!(token.expose(), "sk-secret-12345");
}
