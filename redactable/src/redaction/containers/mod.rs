//! RedactableContainer implementations for standard library types.
//!
//! This module provides `RedactableContainer` implementations for common std
//! containers (`Option`, `Vec`, `Box`, maps, sets). When walking into these
//! containers, they recursively apply redaction to their contents.
//!
//! ## Map Keys Are Not Redacted
//!
//! For map containers (`HashMap`, `BTreeMap`), only **values** are redacted.
//! Keys are left untouched by design to preserve hashing/ordering invariants.
//! Do not place sensitive data in map keys unless you intend it to remain visible.
//!
//! ## Set Redaction Can Collapse Elements
//!
//! For set containers (`HashSet`, `BTreeSet`), redaction is applied to each
//! element and the results are collected back into a set. If redaction changes
//! equality or ordering (e.g., multiple values redact to `"[REDACTED]"`), the
//! resulting set may shrink.

mod cells;
#[cfg(feature = "ip-address")]
mod ip_address;
mod maps;
mod passthrough;
mod sets;
mod wrappers;

#[cfg(test)]
mod tests;

// =============================================================================
// Passthrough implementation helper
// =============================================================================

macro_rules! impl_redactable_container_passthrough {
    ($ty:ty) => {
        impl crate::redaction::traits::RedactableContainer for $ty {
            fn redact_with<M: crate::redaction::redact::RedactableMapper>(
                self,
                _mapper: &M,
            ) -> Self {
                self
            }
        }
    };
}

pub(super) use impl_redactable_container_passthrough;
