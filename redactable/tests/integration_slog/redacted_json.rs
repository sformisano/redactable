use crate::log_redacted;
use redactable::{RedactedJsonExt, RedactedOutputView, Secret, Sensitive};
use serde::Serialize;

#[test]
fn produces_json_output() {
    #[derive(Clone, Sensitive, Serialize)]
    struct Event {
        #[sensitive(Secret)]
        token: String,
        #[not_sensitive]
        user: String,
    }

    let event = Event {
        token: "secret".into(),
        user: "alice".into(),
    };

    let output = log_redacted(&event.redacted_json());
    if let RedactedOutputView::Json(json) = output.view() {
        assert_eq!(json["token"], "[REDACTED]");
        assert_eq!(json["user"], "alice");
    } else {
        panic!("Expected Json output");
    }
}
