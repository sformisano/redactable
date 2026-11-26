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

    redactable::info!(sink, secret = raw; "raw string");
    redactable::warn!(sink, count = number; "raw number");
    redactable::error!(sink, valid = (), bad = custom, valid_again = (); "mixed");
    redactable::debug!(sink, secret:% = raw; "raw display");
    redactable::trace!(sink, secret:? = raw; "raw debug");
}

fn main() {}
