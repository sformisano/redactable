//! A raw passthrough value must not satisfy `Redactable` at all.
//!
//! `Redactable` is the certification: it is implemented by the derives, the
//! wrapper types, and containers of them - never by bare leaves. Before 0.9,
//! `Redactable` was blanket-implemented over the traversal machinery, so
//! `password.redact()` compiled and "redacted" a bare string to itself.

use redactable::Redactable;

fn require_redactable<T: Redactable>(_: &T) {}

fn main() {
    let password = String::from("hunter2");
    require_redactable(&password);
}
