use redactable::{NotSensitiveDebug, NotSensitiveDisplay};
use serde::Serialize;

fn require_serialize<T: Serialize>(_: &T) {}

fn main() {
    require_serialize(&NotSensitiveDebug(1_u8));
    require_serialize(&NotSensitiveDisplay(1_u8));
}
