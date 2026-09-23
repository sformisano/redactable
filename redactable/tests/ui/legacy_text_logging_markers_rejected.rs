#![allow(deprecated)]

use redactable::BypassTextRedaction;

#[cfg(feature = "slog")]
fn needs_slog<T: redactable::slog::SlogRedacted>() {}

#[cfg(feature = "tracing")]
fn needs_tracing<T: redactable::tracing::TracingRedacted>() {}

fn main() {
    #[cfg(feature = "slog")]
    needs_slog::<BypassTextRedaction>();

    #[cfg(feature = "tracing")]
    needs_tracing::<BypassTextRedaction>();
}
