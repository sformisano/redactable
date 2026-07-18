use super::*;

#[test]
fn redacts_vec_elements() {
    #[derive(Clone, Sensitive, Serialize)]
    struct ApiKeys {
        #[sensitive(Token)]
        keys: Vec<String>,
    }

    let list = ApiKeys {
        keys: vec![
            "sk_live_abc123def456".into(),
            "sk_test_xyz789ghi012".into(),
            "pk_live_jkl345mno678".into(),
        ],
    };

    let redacted = list.slog_redacted_json();

    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&redacted, "list", &mut serializer);

    if let Some(CapturedValue::Serde(json)) = serializer.get("list") {
        let keys = json["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].as_str().unwrap(), "****************f456");
        assert_eq!(keys[1].as_str().unwrap(), "****************i012");
        assert_eq!(keys[2].as_str().unwrap(), "****************o678");
    } else {
        panic!("Expected Serde value for 'list' key");
    }
}

#[test]
fn redacts_option_values() {
    #[derive(Clone, Sensitive, Serialize)]
    struct OptionalSensitive {
        #[sensitive(Secret)]
        secret: Option<String>,
        public: String,
    }

    let with_sensitive = OptionalSensitive {
        secret: Some("my_secret".into()),
        public: "visible".into(),
    };

    let redacted = with_sensitive.slog_redacted_json();
    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&redacted, "data", &mut serializer);

    if let Some(CapturedValue::Serde(json)) = serializer.get("data") {
        assert_eq!(json["secret"], "[REDACTED]");
        assert_eq!(json["public"], "visible");
    } else {
        panic!("Expected Serde value");
    }

    let without_sensitive = OptionalSensitive {
        secret: None,
        public: "visible".into(),
    };

    let redacted = without_sensitive.slog_redacted_json();
    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&redacted, "data", &mut serializer);

    if let Some(CapturedValue::Serde(json)) = serializer.get("data") {
        assert!(json["secret"].is_null());
        assert_eq!(json["public"], "visible");
    } else {
        panic!("Expected Serde value");
    }
}

#[test]
fn redacts_hashmap_values() {
    #[derive(Clone, Sensitive, Serialize)]
    struct Config {
        #[sensitive(Secret)]
        secrets: HashMap<String, String>,
    }

    let mut secrets = HashMap::new();
    secrets.insert("api_key".into(), "sk_live_abc123".into());
    secrets.insert("db_password".into(), "p4ssw0rd!".into());

    let config = Config { secrets };
    let redacted = config.slog_redacted_json();

    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&redacted, "config", &mut serializer);

    if let Some(CapturedValue::Serde(json)) = serializer.get("config") {
        let secrets = json["secrets"].as_object().unwrap();
        for (_key, value) in secrets {
            assert_eq!(value, "[REDACTED]");
        }
    } else {
        panic!("Expected Serde value");
    }
}
