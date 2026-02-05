// Test: NotSensitiveDisplay with template compiles without also deriving NotSensitive
// This demonstrates that NotSensitiveDisplay now provides RedactableContainer automatically.

use redactable::{NotSensitiveDisplay, Redactable};

/// status: {status_code}
#[derive(NotSensitiveDisplay)]
struct ApiStatus {
    status_code: u16,
}

/// HTTP response with code {code} and message: {message}
#[derive(NotSensitiveDisplay)]
struct HttpResponse {
    code: u16,
    message: String,
}

fn main() {
    let status = ApiStatus { status_code: 200 };
    let response = HttpResponse {
        code: 404,
        message: "Not Found".into(),
    };

    // Verify RedactableDisplay works
    let displayed = redactable::RedactableDisplay::redacted_display(&status).to_string();
    assert_eq!(displayed, "status: 200");

    let response_displayed = redactable::RedactableDisplay::redacted_display(&response).to_string();
    assert_eq!(response_displayed, "HTTP response with code 404 and message: Not Found");

    // Verify RedactableContainer is implemented (no-op passthrough)
    let status2 = ApiStatus { status_code: 500 };
    let redacted = status2.redact();
    assert_eq!(redacted.status_code, 500); // unchanged
}
