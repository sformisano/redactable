//! `RedactableWithMapper` implementations for standard library types.
//!
//! This module provides `RedactableWithMapper` implementations for common std
//! containers (`Option`, `Vec`, `VecDeque`, arrays, tuples, `Box`, locks, maps,
//! sets). When walking into these containers, they recursively apply redaction
//! to their contents.
//!
//! Passthrough leaf types still are not certified for `.redact()`. Container
//! certification forwards only when the contained values have declared
//! redaction behavior:
//!
//! ```compile_fail
//! use redactable::Redactable;
//!
//! let values = std::collections::VecDeque::from([String::from("raw")]);
//! let _ = values.redact();
//! ```
//!
//! ```compile_fail
//! use redactable::Redactable;
//!
//! let values = [String::from("raw")];
//! let _ = values.redact();
//! ```
//!
//! ```compile_fail
//! use redactable::Redactable;
//!
//! let values = (String::from("raw"),);
//! let _ = values.redact();
//! ```
//!
//! ```compile_fail
//! use redactable::Redactable;
//!
//! let value = std::sync::Mutex::new(String::from("raw"));
//! let _ = value.redact();
//! ```
//!
//! ```compile_fail
//! use redactable::Redactable;
//!
//! let value = std::sync::RwLock::new(String::from("raw"));
//! let _ = value.redact();
//! ```
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
        impl crate::redaction::traits::RedactableWithMapper for $ty {
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
