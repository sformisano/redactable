//! `serde_json::Value` support for redaction traversal.
//!
//! `serde_json::Value` is treated as an opaque leaf type. Any policy application
//! fully redacts it to `Value::String("[REDACTED]")`. Unannotated values also
//! redact by default as an explicit exception to the crate's mostly opt-in
//! model: since `Value` can contain arbitrary data, we redact it entirely rather
//! than attempting to traverse its dynamic structure.

use super::{
    redact::{PolicyApplicable, PolicyApplicableRef, RedactableMapper},
    traits::{Redactable, RedactableWithMapper},
};
use crate::policy::RedactionPolicy;

impl PolicyApplicable for serde_json::Value {
    fn apply_policy<P, M>(self, _mapper: &M) -> Self
    where
        P: RedactionPolicy,
        M: RedactableMapper,
    {
        // Treat as leaf: any policy fully redacts to a JSON string.
        serde_json::Value::String("[REDACTED]".to_string())
    }
}

impl PolicyApplicableRef for serde_json::Value {
    type Output = serde_json::Value;

    fn apply_policy_ref<P, M>(&self, _mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        M: RedactableMapper,
    {
        serde_json::Value::String("[REDACTED]".to_string())
    }
}

impl RedactableWithMapper for serde_json::Value {
    fn redact_with<M: RedactableMapper>(self, _mapper: &M) -> Self {
        // Safe-by-default: unannotated Value fields are fully redacted.
        serde_json::Value::String("[REDACTED]".to_string())
    }
}

// `Value` redaction is declared by the crate itself (full redaction as an
// opaque leaf), so it is certified for the redacted-output extension traits.
impl Redactable for serde_json::Value {}
