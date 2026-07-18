#![no_implicit_prelude]

extern crate redactable;
#[cfg(feature = "slog")]
extern crate serde;

#[derive(redactable::SensitiveDisplay)]
#[error("{value}")]
struct DisplaySecret {
    #[sensitive(redactable::Secret)]
    value: ::std::string::String,
}

#[derive(redactable::NotSensitiveDisplay)]
struct PublicValue;

impl ::core::fmt::Display for PublicValue {
    fn fmt(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        formatter.write_str("public")
    }
}

#[derive(::core::clone::Clone, redactable::Sensitive)]
#[cfg_attr(feature = "slog", derive(serde::Serialize))]
struct StructuralSecret(#[sensitive(redactable::Secret)] ::std::string::String);

fn main() {
    let display = DisplaySecret {
        value: <::std::string::String as ::core::convert::From<&str>>::from("secret-canary"),
    };
    let _ = redactable::ToRedactedOutput::to_redacted_output(&display);
    let _ = redactable::ToRedactedOutput::to_redacted_output(&PublicValue);
    let structural = StructuralSecret(
        <::std::string::String as ::core::convert::From<&str>>::from("secret-canary"),
    );
    let _ = redactable::Redactable::redact(structural);
}
