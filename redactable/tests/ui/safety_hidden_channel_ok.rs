//! The derive channel builds redacted outputs for declared producers.

use redactable::{
    __private::{generated_redacted_display, generated_redacted_json},
    Secret, Sensitive,
};

#[derive(Clone, serde::Serialize, Sensitive)]
struct Protected {
    #[sensitive(Secret)]
    payload: serde_json::Value,
}

fn main() {
    let payload = serde_json::json!({"raw_consumer_payload": "not-redacted-by-anything"});
    assert_eq!(generated_redacted_display(&payload).text(), "[REDACTED]");
    assert_eq!(
        generated_redacted_json(&Protected { payload }).json(),
        serde_json::json!({"payload":"[REDACTED]"})
    );
}
