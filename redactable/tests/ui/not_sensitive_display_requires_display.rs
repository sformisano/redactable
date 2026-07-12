use redactable::{NotSensitiveDisplay, ToRedactedOutput};

struct NoDisplay;

fn require_output<T: ToRedactedOutput>(_: &T) {}

fn main() {
    require_output(&NotSensitiveDisplay(NoDisplay));
}
