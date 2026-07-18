use super::*;

#[test]
fn redacts_simple_struct() {
    #[derive(Clone, Sensitive, Serialize)]
    struct User {
        username: String,
        #[sensitive(Secret)]
        password: String,
    }

    let user = User {
        username: "alice".into(),
        password: "super_secret_password".into(),
    };

    let redacted = user.slog_redacted_json();

    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&redacted, "user", &mut serializer);

    if let Some(CapturedValue::Serde(json)) = serializer.get("user") {
        assert_eq!(json["username"], "alice");
        assert_eq!(json["password"], "[REDACTED]");
    } else {
        panic!("Expected Serde value for 'user' key");
    }
}

#[test]
fn applies_different_policies() {
    #[derive(Clone, Sensitive, Serialize)]
    struct Contact {
        #[sensitive(Email)]
        email: String,
        #[sensitive(PhoneNumber)]
        phone: String,
        #[sensitive(Pii)]
        full_name: String,
    }

    let contact = Contact {
        email: "alice@example.com".into(),
        phone: "555-123-4567".into(),
        full_name: "Alice Smith".into(),
    };

    let redacted = contact.slog_redacted_json();

    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&redacted, "contact", &mut serializer);

    if let Some(CapturedValue::Serde(json)) = serializer.get("contact") {
        assert_eq!(json["email"].as_str().unwrap(), "al***@example.com");
        assert_eq!(json["phone"].as_str().unwrap(), "********4567");
        assert_eq!(json["full_name"].as_str().unwrap(), "*********th");
    } else {
        panic!("Expected Serde value for 'contact' key");
    }
}
