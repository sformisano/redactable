use super::*;

#[test]
fn slog_serialization_emits_redacted_value() {
    let token = SensitiveValue::<String, Token>::from(String::from("sk-secret-12345"));

    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&token, "token", &mut serializer);

    if let Some(CapturedValue::Str(value)) = serializer.get("token") {
        assert_eq!(value, "***********2345");
    } else {
        panic!("Expected Str value for 'token' key");
    }
}
