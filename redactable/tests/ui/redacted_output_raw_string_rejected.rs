//! A raw passthrough value must not satisfy `RedactedOutputExt`.
//!
//! `Redactable` is blanket-implemented over no-op passthrough leaves, so
//! before `DeclaredRedactable` gated the extension trait,
//! `password.redacted_output()` compiled and certified the raw string as
//! redacted output with zero transformation.

use redactable::RedactedOutputExt;

fn require_certified<T: RedactedOutputExt>(_: &T) {}

fn main() {
    let password = String::from("hunter2");
    require_certified(&password);
}
