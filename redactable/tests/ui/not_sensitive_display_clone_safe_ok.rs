use std::fmt;

use redactable::{NotSensitiveDisplay, ToRedacted};

#[derive(Clone, NotSensitiveDisplay, serde::Serialize)]
struct Generic<T>(T);

impl<T: fmt::Display> fmt::Display for Generic<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

fn main() {
    let value = Generic(String::from("safe"));
    let _ = value.to_redacted();
}
