use redactable::{BypassDebugRedaction, ToRedacted};

struct NoDebug;

fn require_output<T: ToRedacted>(_: &T) {}

fn main() {
    require_output(&BypassDebugRedaction(NoDebug));
}
