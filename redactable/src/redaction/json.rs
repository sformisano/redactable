//! `serde_json::Value` support for redaction traversal.
//!
//! Low-level traversal and supported recursive policies mask the complete JSON
//! value. Structural derives require an explicit field declaration because
//! native `Debug` would otherwise print the original payload.

use serde_json::Value;

use super::{
    redact::{PolicyApplicable, PolicyApplicableRef, RedactableMapper},
    traits::RedactableWithMapper,
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
        // Erased JSON has no field policies; this structural path emits an opaque placeholder.
        Value::String("[REDACTED]".to_string())
    }
}
