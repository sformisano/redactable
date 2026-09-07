//! `serde_json::Value` support for redaction traversal.
//!
//! `serde_json::Value` is an opaque leaf with built-in `Redactable` behavior.
//! Default traversal and supported recursive policy application fully redact it
//! to `Value::String("[REDACTED]")`. They do not traverse its dynamic structure.
//! Policy application retains its policy-kind bounds; typed IP dispatch is separate.

use serde_json::Value;

use super::{
    redact::{PolicyApplicable, PolicyApplicableRef, RedactableMapper},
    traits::{Redactable, RedactableWithMapper},
};
use crate::policy::{RecursivePolicyKind, RedactionPolicy};

impl PolicyApplicable for Value {
    fn apply_policy<P, M>(self, _mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        // Supported recursive policies fully redact this opaque leaf to a JSON string.
        Value::String("[REDACTED]".to_string())
    }
}

impl PolicyApplicableRef for Value {
    type Output = Value;

    fn apply_policy_ref<P, M>(&self, _mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        Value::String("[REDACTED]".to_string())
    }
}

impl RedactableWithMapper for Value {
    fn redact_with<M: RedactableMapper>(self, _mapper: &M) -> Self {
        // Safe-by-default: unannotated Value fields are fully redacted.
        Value::String("[REDACTED]".to_string())
    }
}

// `Value` redaction is declared by the crate itself (full redaction as an
// opaque leaf), so it is certified for the redacted-output extension traits.
impl Redactable for Value {}
