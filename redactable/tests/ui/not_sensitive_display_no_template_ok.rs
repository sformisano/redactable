// Test: NotSensitiveDisplay without template delegates to Display (unchanged behavior)
// Also verifies RedactableContainer is generated even without a template.

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

    // Verify RedactableDisplay delegates to Display
    let displayed = redactable::RedactableDisplay::redacted_display(&method).to_string();
    assert_eq!(displayed, "GET");

    // Verify RedactableContainer is implemented (no-op passthrough)
    let method2 = HttpMethod("POST".into());
    let redacted = method2.redact();
    assert_eq!(redacted.0, "POST"); // unchanged
}
