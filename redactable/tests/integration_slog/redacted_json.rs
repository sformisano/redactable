//! The derived producer carries the redacted JSON; there is no lazy bridge.

use crate::log_redacted;
use redactable::{Secret, Sensitive};
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

    let json = log_redacted(&event).json();
    assert_eq!(json["token"], "[REDACTED]");
    assert_eq!(json["user"], "alice");
}
