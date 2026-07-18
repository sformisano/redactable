use super::*;

#[test]
fn redacts_enum_variants() {
    #[derive(Clone, Sensitive, Serialize)]
    enum Credential {
        ApiKey {
            #[sensitive(Token)]
            key: String,
        },
        Password {
            username: String,
            #[sensitive(Secret)]
            password: String,
        },
    }

    let api_key = Credential::ApiKey {
        key: "sk_live_abc123def456".into(),
    };

    let redacted = api_key.slog_redacted_json();
    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&redacted, "cred", &mut serializer);

    if let Some(CapturedValue::Serde(json)) = serializer.get("cred") {
        let key = json["ApiKey"]["key"].as_str().unwrap();
        assert_eq!(key, "****************f456");
    } else {
        panic!("Expected Serde value");
    }

    let password = Credential::Password {
        username: "admin".into(),
        password: "supersecret".into(),
    };

    let redacted = password.slog_redacted_json();
    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&redacted, "cred", &mut serializer);

    if let Some(CapturedValue::Serde(json)) = serializer.get("cred") {
        assert_eq!(json["Password"]["username"], "admin");
        assert_eq!(json["Password"]["password"], "[REDACTED]");
    } else {
        panic!("Expected Serde value");
    }
}
