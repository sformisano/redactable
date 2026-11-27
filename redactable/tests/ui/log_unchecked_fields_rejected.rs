use std::borrow::Cow;

#[cfg(feature = "log")]
use ::log::kv::{ToValue, Value};
use redactable::{RedactedValue, ToRedacted, logging::Sink};

#[derive(Debug, serde::Serialize)]
struct Undeclared;

#[cfg(feature = "log")]
impl ToValue for Undeclared {
    fn to_value(&self) -> Value<'_> {
        Value::from_serde(self)
    }
}

impl Undeclared {
    fn to_redacted(&self) -> RedactedValue {
        ().to_redacted()
    }

    fn to_redacted_cow(&self) -> Cow<'_, RedactedValue> {
        Cow::Owned(self.to_redacted())
    }
}

fn unchecked(sink: &Sink) {
    let raw = String::from("raw");
    let number = 42_u32;
    let custom = Undeclared;
    let _ = custom.to_redacted_cow();
    #[cfg(feature = "log")]
    ::log::info!(raw = raw, number = number, custom = custom; "ordinary log");

    redactable::info!(raw; "raw shorthand");
    redactable::warn!(count = number; "raw number");
    redactable::error!(valid = (), bad = custom, valid_again = (); "mixed");
    redactable::debug!(sink: sink, secret:% = raw; "raw display");
    redactable::trace!(secret:? = raw; "raw debug");
    redactable::info!("unchecked {}", raw);
    redactable::info!(valid = (); "approved {ok} and unchecked {who:?}", ok = (), who = custom);
}

fn main() {}
