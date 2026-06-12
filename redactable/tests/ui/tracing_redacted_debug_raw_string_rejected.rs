//! A raw passthrough value must not satisfy `TracingRedactedDebugExt`.
//!
//! The helper is for structural values with declared redaction behavior. Raw
//! leaves like `String` can participate inside a `Sensitive` container, but
//! they cannot certify their own tracing output.

use redactable::tracing::TracingRedactedDebugExt;

fn require_tracing_debug<T: TracingRedactedDebugExt>(_: &T) {}

fn main() {
    let password = String::from("hunter2");
    require_tracing_debug(&password);
}
