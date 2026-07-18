use super::*;

#[test]
fn produces_json_output() {
    #[derive(Clone, Sensitive, Serialize)]
    struct Event {
        #[sensitive(Secret)]
        token: String,
        user: String,
    }

    let event = Event {
        token: "secret".into(),
        user: "alice".into(),
    };

    let output = log_redacted(&event.redacted_json());
    if let RedactedOutput::Json(json) = output {
        assert_eq!(json["token"], "[REDACTED]");
        assert_eq!(json["user"], "alice");
    } else {
        panic!("Expected Json output");
    }
}
