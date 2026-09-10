use std::fmt;

use redactable::ToRedacted;

struct DisplayOnly;

impl fmt::Display for DisplayOnly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("raw")
    }
}

fn require_output<T: ToRedacted>(_: &T) {}

fn main() {
    require_output(&DisplayOnly);
}
