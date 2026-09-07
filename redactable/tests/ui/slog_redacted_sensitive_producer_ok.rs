//! `.slog_redacted()` accepts a producer with no formatter.
//!
//! A plain `Sensitive` struct implements `ToRedacted` but not
//! `RedactableWithFormatter`. Keeping the formatter bound on the
//! `RedactedDisplayValue` impls would make the value returned here fail the
//! `slog::Value` bound at the `info!` site.

use redactable::slog::SlogRedactedExt;
use redactable::{Secret, Sensitive};

#[derive(Clone, serde::Serialize, Sensitive)]
struct Event {
    #[sensitive(Secret)]
    token: String,
}

fn main() {
    let event = Event {
        token: String::from("secret"),
    };
    let logger = ::slog::Logger::root(::slog::Discard, ::slog::o!());
    ::slog::info!(logger, "event"; "text" => event.slog_redacted(), "json" => event.slog_redacted_json());
}
