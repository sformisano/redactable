use std::fmt;

use redactable::ToRedactedOutput;

struct DebugOnly;

impl fmt::Debug for DebugOnly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("raw")
    }
}

fn require_output<T: ToRedactedOutput>(_: &T) {}

fn main() {
    require_output(&DebugOnly);
}
