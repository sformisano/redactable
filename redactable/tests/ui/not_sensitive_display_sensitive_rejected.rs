// Test: NotSensitiveDisplay rejects #[sensitive(...)] attributes

use redactable::NotSensitiveDisplay;

/// bad request: {message}
#[derive(NotSensitiveDisplay)]
struct BadRequest {
    #[sensitive(redactable::Secret)]
    message: String,
}

fn main() {}
