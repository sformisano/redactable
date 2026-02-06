// Test: NotSensitiveDisplay on an enum with foreign type fields (std::io::Error,
// std::num::ParseIntError) and a manual Display impl. No #[not_sensitive] needed.
// This would have failed before the change because the template-based path
// required fields to implement RedactableDisplay.

use std::fmt;

use redactable::NotSensitiveDisplay;

#[derive(NotSensitiveDisplay)]
enum MyError {
    Io(std::io::Error),
    Parse(std::num::ParseIntError),
}

impl fmt::Display for MyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MyError::Io(e) => write!(f, "IO error: {e}"),
            MyError::Parse(e) => write!(f, "parse error: {e}"),
        }
    }
}

fn main() {
    let io_err = MyError::Io(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "file missing",
    ));
    let parse_err = MyError::Parse("abc".parse::<i32>().unwrap_err());

    // Verify RedactableDisplay delegates to Display
    let io_displayed = redactable::RedactableDisplay::redacted_display(&io_err).to_string();
    assert_eq!(io_displayed, "IO error: file missing");

    let parse_displayed = redactable::RedactableDisplay::redacted_display(&parse_err).to_string();
    assert_eq!(parse_displayed, "parse error: invalid digit found in string");
}
