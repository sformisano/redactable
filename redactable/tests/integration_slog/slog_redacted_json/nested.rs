use super::*;

#[test]
fn redacts_nested_struct() {
    #[derive(Clone, Sensitive, Serialize)]
    struct Address {
        #[sensitive(Pii)]
        street: String,
        city: String,
    }

    #[derive(Clone, Sensitive, Serialize)]
    struct Person {
        name: String,
        #[sensitive(Secret)]
        ssn: String,
        address: Address,
    }

    let person = Person {
        name: "Bob".into(),
        ssn: "123-45-6789".into(),
        address: Address {
            street: "123 Main Street".into(),
            city: "Springfield".into(),
        },
    };

    let redacted = person.slog_redacted_json();

    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&redacted, "person", &mut serializer);

    if let Some(CapturedValue::Serde(json)) = serializer.get("person") {
        assert_eq!(json["name"], "Bob");
        assert_eq!(json["ssn"], "[REDACTED]");
        assert_eq!(
            json["address"]["street"].as_str().unwrap(),
            "*************et"
        );
        assert_eq!(json["address"]["city"], "Springfield");
    } else {
        panic!("Expected Serde value for 'person' key");
    }
}
