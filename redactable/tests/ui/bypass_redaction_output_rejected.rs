use redactable::{BypassRedaction, ToRedacted};

fn require_output<T: ToRedacted>(_: &T) {}

fn main() {
    require_output(&BypassRedaction(String::from("ambiguous")));
}
