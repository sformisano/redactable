use redactable::{NotSensitiveDebug, ToRedactedOutput};

struct NoDebug;

fn require_output<T: ToRedactedOutput>(_: &T) {}

fn main() {
    require_output(&NotSensitiveDebug(NoDebug));
}
