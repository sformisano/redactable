//! The doc-hidden derive channel accepts declared types, never payloads.
//!
//! This is the falsification probe a reviewer ran against the previous round: a
//! consumer reaching into `redactable::__private` with an arbitrary
//! `serde_json::Value`, a raw string, and a text/JSON pair. Each helper now
//! borrows a value whose type carries the matching declaration and performs the
//! redaction or serialization itself, so none of these calls compiles.

use redactable::__private::{
    generated_declared_json, generated_redacted_display, generated_redacted_dual,
    generated_redacted_json,
};

fn main() {
    let arbitrary = serde_json::json!({"raw_consumer_payload": "not-redacted-by-anything"});
    // No payload argument: the helper redacts a declared value itself.
    let _ = generated_redacted_json(arbitrary.clone());
    let _ = generated_redacted_dual(&arbitrary, arbitrary.clone());
    // No undeclared type reaches any of them.
    let _ = generated_redacted_display("plain");
    let _ = generated_redacted_json(&String::from("raw"));
    let _ = generated_declared_json(&String::from("raw"));
}
