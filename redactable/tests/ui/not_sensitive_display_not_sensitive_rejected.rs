// Test: NotSensitiveDisplay rejects #[not_sensitive] attributes on fields

use redactable::NotSensitiveDisplay;

#[derive(NotSensitiveDisplay)]
enum MyError {
    Io(#[not_sensitive] std::io::Error),
}

fn main() {}
