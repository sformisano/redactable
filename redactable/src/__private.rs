//! Private compile-time support used by derive-generated policy operations.
//!
//! Field behavior is selected by `RedactionPolicy::Kind`. Text and secret kinds
//! retain recursive compatibility traversal, while IP kinds use a positive,
//! fail-closed structural traversal with safe map-key bounds.

mod field;
mod formatting;
mod kinds;
mod output;

#[doc(hidden)]
pub use crate::redaction::{IpPolicyApplicable, IpPolicyApplicableRef};

/// Fail-closed JSON serialization used by redacted logging adapters.
#[cfg(feature = "json")]
pub use crate::redaction::serialize_redacted_json;
/// Serialization support used by derive-generated slog implementations.
#[cfg(feature = "json")]
pub use serde;
/// JSON support used by derive-generated slog implementations.
#[cfg(feature = "slog")]
pub use serde_json;
/// Logging support used by derive-generated slog implementations.
#[cfg(feature = "slog")]
pub use slog;

/// Default mapper used by generated private field operations.
pub use crate::redaction::{PolicyFormattingMapper, PolicyMapper};

pub use field::{
    PolicyApplicableRefForFormatting, PolicyApplicableRefForGeneratedFormatting, PolicyField,
    PolicyFieldRef, PolicyFieldRefForFormatting, PolicyKindField, PolicyKindFieldRef,
    PolicyKindFieldRefForFormatting, RecursivePolicyField,
};
pub use formatting::{
    ExplicitLegacyPolicyFormattingRef, GeneratedPolicyFormattingRef, LegacyPolicyFormattingRef,
    PolicyFormattingDispatch, PolicyFormattingProbe, PolicyFormattingRef,
    legacy_policy_formatting_ref, policy_formatting_probe, policy_formatting_ref,
};
pub use kinds::{
    GeneratedPolicyKindDebugFormatting, GeneratedPolicyKindDisplayFormatting,
    PolicyKindDebugFormatting, PolicyKindDisplayFormatting,
};
pub use output::{PolicyFormattingOutput, PolicyRefCellOutput};

/// Constructs generated borrowed slog output without exposing internal constructors.
#[cfg(feature = "slog")]
#[doc(hidden)]
pub fn generated_redacted_json(value: serde_json::Value) -> crate::RedactedJson {
    crate::RedactedJson::new(value)
}
