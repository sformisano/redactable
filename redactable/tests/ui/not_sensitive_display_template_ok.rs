// Test: NotSensitiveDisplay with doc-comment templates delegates to Display.
// After the simplification, NotSensitiveDisplay always delegates to Display::fmt,
// so the type must implement Display (e.g. via displaydoc or a manual impl).

use std::fmt;

use redactable::{NotSensitiveDisplay, Redactable};

/// status: {status_code}
#[derive(NotSensitiveDisplay)]
struct ApiStatus {
    status_code: u16,
}

impl fmt::Display for ApiStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "status: {}", self.status_code)
    }
}

/// HTTP response with code {code} and message: {message}
#[derive(NotSensitiveDisplay)]
struct HttpResponse {
    code: u16,
    message: String,
}

impl fmt::Display for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HTTP response with code {} and message: {}",
            self.code, self.message
        )
    }
}

fn main() {
    let status = ApiStatus { status_code: 200 };
    let response = HttpResponse {
        code: 404,
        message: "Not Found".into(),
    };

    // Verify RedactableDisplay delegates to Display
    let displayed = redactable::RedactableDisplay::redacted_display(&status).to_string();
    assert_eq!(displayed, "status: 200");

    let response_displayed =
        redactable::RedactableDisplay::redacted_display(&response).to_string();
    assert_eq!(
        response_displayed,
        "HTTP response with code 404 and message: Not Found"
    );

    // Verify RedactableContainer is implemented (no-op passthrough)
    let status2 = ApiStatus { status_code: 500 };
    let redacted = status2.redact();
    assert_eq!(redacted.status_code, 500); // unchanged
}
