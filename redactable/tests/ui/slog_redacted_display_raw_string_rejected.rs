//! `.slog_redacted_display()` on a raw passthrough value must not compile.
//!
//! `RedactableWithFormatter` is implemented as passthrough for `String` and
//! scalars so they can format inside redacted templates. Before
//! `DeclaredRedactable` gated the extension trait, this compiled, emitted the
//! raw value to slog, and carried the `SlogRedacted` certification marker.

use redactable::slog::SlogRedactedDisplayExt;

fn main() {
    let password = String::from("hunter2");
    let _ = password.slog_redacted_display();
}
