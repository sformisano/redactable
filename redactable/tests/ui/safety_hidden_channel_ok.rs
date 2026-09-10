//! The one declared type a consumer can still hand the channel is redacted.
//!
//! `serde_json::Value` has crate-declared redaction behavior (full redaction as
//! an opaque leaf), so it satisfies the helpers' bounds. The channel therefore
//! answers with the placeholder rather than the caller's payload, which is the
//! property the bounds exist to keep.

use redactable::__private::{generated_redacted_display, generated_redacted_json};

fn main() {
    let arbitrary = serde_json::json!({"raw_consumer_payload": "not-redacted-by-anything"});

    assert_eq!(
        generated_redacted_json(&arbitrary).json(),
        serde_json::json!("[REDACTED]")
    );
    assert_eq!(generated_redacted_display(&arbitrary).text(), "[REDACTED]");
}
