use std::fmt;

use redactable::ToRedactedOutput;

struct DisplayOnly;

impl fmt::Display for DisplayOnly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("raw")
    }
}

fn require_output<T: ToRedactedOutput>(_: &T) {}

fn main() {
    require_output(&DisplayOnly);
}
