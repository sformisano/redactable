// Test: NotSensitiveDisplay without template delegates to Display (unchanged behavior)
// Also verifies RedactableWithMapper is generated even without a template.

use std::fmt;

use redactable::{NotSensitiveDisplay, Redactable};

#[derive(NotSensitiveDisplay)]
struct HttpMethod(String);

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn main() {
    let method = HttpMethod("GET".into());

    // Verify RedactableWithFormatter delegates to Display
    let displayed = redactable::RedactableWithFormatter::redacted_display(&method).to_string();
    assert_eq!(displayed, "GET");

    // Verify RedactableWithMapper is implemented (no-op passthrough)
    let method2 = HttpMethod("POST".into());
    let redacted = method2.redact();
    assert_eq!(redacted.0, "POST"); // unchanged
}
