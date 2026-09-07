//! `BypassRedactionMarker` certifies a value for slog's native typed emitter.
//!
//! It is the only member of the family that keeps the emitted type instead of
//! flattening it, and the only one that accepts a type implementing neither
//! `Display` nor `Debug`.

use redactable::BypassRedactionMarker;
use redactable::slog::SlogRedacted;

struct NoFormatting;

fn assert_slog_redacted<T: SlogRedacted>(_: &T) {}

fn main() {
    let count = BypassRedactionMarker(7_u64);
    assert_slog_redacted(&count);
    let logger = ::slog::Logger::root(::slog::Discard, ::slog::o!());
    ::slog::info!(logger, "event"; "count" => count);
    let opaque = BypassRedactionMarker(NoFormatting);
    let NoFormatting = opaque.0;
}
