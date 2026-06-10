//! `.redacted_output()` on a raw passthrough value must not compile.
//!
//! `Redactable` is blanket-implemented over no-op passthrough leaves, so
//! before `DeclaredRedactable` gated the extension trait, this compiled and
//! certified the raw string as redacted output with zero transformation.

use redactable::RedactedOutputExt;

fn main() {
    let password = String::from("hunter2");
    let _ = password.redacted_output();
}
