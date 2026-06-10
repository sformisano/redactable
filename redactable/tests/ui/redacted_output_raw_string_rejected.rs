//! A raw passthrough value must not satisfy `RedactedOutputExt`.
//!
//! `Redactable` is only implemented by types with declared redaction behavior.
//! Before 0.9 it was blanket-implemented over no-op passthrough leaves, so
//! `password.redacted_output()` compiled and certified the raw string as
//! redacted output with zero transformation.

use redactable::RedactedOutputExt;

fn require_certified<T: RedactedOutputExt>(_: &T) {}

fn main() {
    let password = String::from("hunter2");
    require_certified(&password);
}
