//! Application layer: Redaction machinery.
//!
//! This module provides the infrastructure for applying redaction:
//!
//! - [`RedactableMapper`]: Internal trait for mapping values during traversal
//! - [`PolicyApplicable`]: Types that can have policies applied recursively
//! - [`redact`]: The entry point function for redacting a value
//! - [`ScalarRedaction`]: Helper trait for scalar default values
//!
//! ## How `PolicyApplicable` Works
//!
//! For a field like:
//! ```ignore
//! #[sensitive(Token)]
//! api_keys: Option<Vec<String>>
//! ```
//!
//! The generated code calls:
//! ```ignore
//! PolicyApplicable::apply_policy::<Token, _>(api_keys, mapper)
//! ```
//!
//! At runtime, this recursively descends:
//! 1. `Option<Vec<String>>` → calls `.map(|v| v.apply_policy::<Token, _>(mapper))`
//! 2. `Vec<String>` → calls `.into_iter().map(|v| v.apply_policy::<Token, _>(mapper)).collect()`
//! 3. `String` → calls `mapper.map_sensitive::<_, Token>(self)`
//!
//! The recursion handles any nesting depth automatically!

mod borrowed;
mod core;
mod leaf;
mod maps;
mod owned;
mod sets;
#[cfg(test)]
mod tests;

pub use core::{
    PolicyApplicable, PolicyApplicableRef, PolicyFormattingMapper, PolicyMapper, RedactableMapper,
    ScalarRedaction, apply_policy, apply_policy_ref, redact,
};
pub use maps::PolicyMapOutput;
