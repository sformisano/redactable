use redactable::{BypassDisplayRedaction, ToRedacted};

struct NoDisplay;

fn require_output<T: ToRedacted>(_: &T) {}

fn main() {
    require_output(&BypassDisplayRedaction(NoDisplay));
}
