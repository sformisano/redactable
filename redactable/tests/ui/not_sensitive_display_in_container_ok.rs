// Test: NotSensitiveDisplay can be used inside #[derive(Sensitive)] container
// This works because NotSensitiveDisplay now provides RedactableContainer.

use redactable::{NotSensitiveDisplay, Redactable, Secret, Sensitive};
use serde::Serialize;

/// error code {code}
#[derive(Clone, Serialize, NotSensitiveDisplay)]
struct ErrorCode {
    code: u16,
}

// This container has a field using NotSensitiveDisplay type
// Previously this required both NotSensitive AND NotSensitiveDisplay on ErrorCode
#[derive(Clone, Serialize, Sensitive)]
struct ApiError {
    error: ErrorCode,
    #[sensitive(Secret)]
    internal_message: String,
}

fn main() {
    let api_error = ApiError {
        error: ErrorCode { code: 500 },
        internal_message: "database connection failed".into(),
    };

    // Verify the container can be redacted (requires ErrorCode: RedactableContainer)
    let redacted = api_error.redact();

    // Error code passes through unchanged (no-op RedactableContainer)
    assert_eq!(redacted.error.code, 500);
    // Sensitive field is redacted
    assert_eq!(redacted.internal_message, "[REDACTED]");
}
