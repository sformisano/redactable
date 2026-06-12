//! Adapters for emitting redacted values through `tracing`.
//!
//! This module provides three explicit tracing paths:
//!
//! - **[`TracingRedactedDebugExt`]**: redacts a structural [`Redactable`] value
//!   before handing its `Debug` form to tracing.
//!
//! - **[`TracingRedactedExt`]**: logs `ToRedactedOutput` values as display
//!   strings. Works with any tracing subscriber but loses structure.
//!
//! - **[`TracingValuableExt`]** (requires the `tracing-valuable` feature and
//!   `RUSTFLAGS="--cfg tracing_unstable"`): logs redacted values as structured
//!   data via the `valuable` crate.
//!
//! # Example
//!
//! ```no_run
//! # #![allow(hidden_glob_reexports)]
//! # pub use redactable::*;
//! use redactable::{Secret, Sensitive, SensitiveValue};
//! use redactable::tracing::{TracingRedactedDebugExt, TracingRedactedExt};
//!
//! #[derive(Clone, Sensitive, serde::Serialize)]
//! struct User {
//!     name: String,
//!     #[sensitive(Secret)]
//!     token: String,
//! }
//!
//! # fn main() {
//! let user = User {
//!     name: "alice".to_owned(),
//!     token: "api-token".to_owned(),
//! };
//! let leaf_token = SensitiveValue::<String, Secret>::from("api-token".to_owned());
//!
//! ::tracing::info!(
//!     user = user.tracing_redacted_debug(),
//!     leaf_token = leaf_token.tracing_redacted(),
//! );
//! # }
//! ```

use std::fmt;

#[cfg(feature = "json")]
use serde::Serialize;
use tracing::field::{DebugValue, DisplayValue, debug, display};

use crate::{
    policy::RedactionPolicy,
    redaction::{
        NotSensitive, NotSensitiveDebug, NotSensitiveDisplay, NotSensitiveJson, Redactable,
        RedactedJson, RedactedJsonRef, RedactedOutput, RedactedOutputRef, SensitiveValue,
        SensitiveWithPolicy, ToRedactedOutput,
    },
};

/// Marker trait for types whose `tracing` integration always emits redacted output.
///
/// This marker indicates that the type will produce redacted output when used
/// with tracing (via `TracingRedactedDebugExt`, `TracingRedactedExt`, or
/// `TracingValuableExt`).
///
/// This trait is implemented only for sink adapters and wrappers that redact
/// before logging. It is not a blanket impl for raw types.
pub trait TracingRedacted {}

/// Extension trait for logging structural redacted values as `Debug` fields.
///
/// This is the plain `tracing` path for types that derive `Sensitive` or
/// otherwise implement [`Redactable`]. The helper clones and redacts the value
/// before it reaches the subscriber, then records the redacted clone through
/// `tracing::field::debug`.
pub trait TracingRedactedDebugExt: Redactable + Clone + fmt::Debug {
    /// Redacts the value and wraps the redacted clone for `tracing` debug
    /// recording.
    fn tracing_redacted_debug(&self) -> DebugValue<Self>;
}

impl<T> TracingRedactedDebugExt for T
where
    T: Redactable + Clone + fmt::Debug,
{
    fn tracing_redacted_debug(&self) -> DebugValue<Self> {
        debug(self.clone().redact())
    }
}

/// Extension trait for logging redacted values as display strings.
///
/// This works with any tracing subscriber but the output is a flat string,
/// not structured data. For structural `Debug` output, use
/// [`TracingRedactedDebugExt`]. For structured `valuable` output, see
/// [`TracingValuableExt`].
pub trait TracingRedactedExt {
    /// Wraps the value for `tracing` logging as a display value.
    ///
    /// The value is redacted and converted to a string representation.
    fn tracing_redacted(&self) -> DisplayValue<String>;
}

impl<T> TracingRedactedExt for T
where
    T: ToRedactedOutput,
{
    fn tracing_redacted(&self) -> DisplayValue<String> {
        let output = self.to_redacted_output();
        let text = match output {
            RedactedOutput::Text(text) => text,
            #[cfg(feature = "json")]
            RedactedOutput::Json(json) => json.to_string(),
        };
        display(text)
    }
}

impl TracingRedacted for RedactedOutput {}

#[cfg(feature = "json")]
impl TracingRedacted for RedactedJson {}

impl<T, P> TracingRedacted for SensitiveValue<T, P>
where
    T: SensitiveWithPolicy<P>,
    P: RedactionPolicy,
{
}

impl<T> TracingRedacted for NotSensitiveDisplay<T> where T: fmt::Display {}

impl<T> TracingRedacted for NotSensitiveDebug<T> where T: fmt::Debug {}

impl<T> TracingRedacted for NotSensitive<T> where T: TracingRedacted {}

impl<T> TracingRedacted for RedactedOutputRef<'_, T> where T: Redactable + Clone + fmt::Debug {}

#[cfg(feature = "json")]
impl<T> TracingRedacted for NotSensitiveJson<'_, T> where T: Serialize + ?Sized {}

#[cfg(feature = "json")]
impl<T> TracingRedacted for RedactedJsonRef<'_, T> where T: Redactable + Clone + Serialize {}

/// A redacted value that implements `valuable::Valuable` for structured tracing output.
///
/// This wrapper is constructed by [`TracingValuableExt::tracing_redacted_valuable`]
/// so callers cannot build structured tracing payloads without first applying
/// redaction. Pass a reference to the wrapper through `tracing::field::valuable`
/// when compiling with `RUSTFLAGS="--cfg tracing_unstable"`.
#[cfg(feature = "tracing-valuable")]
#[derive(Clone, Debug)]
pub struct RedactedValuable<T> {
    redacted: T,
}

#[cfg(feature = "tracing-valuable")]
impl<T> RedactedValuable<T> {
    /// Creates a new `RedactedValuable` from an already-redacted value.
    pub(crate) fn new(redacted: T) -> Self {
        Self { redacted }
    }

    /// Returns a reference to the redacted inner value.
    pub fn inner(&self) -> &T {
        &self.redacted
    }
}

#[cfg(feature = "tracing-valuable")]
impl<T: valuable::Valuable> valuable::Valuable for RedactedValuable<T> {
    fn as_value(&self) -> valuable::Value<'_> {
        self.redacted.as_value()
    }

    fn visit(&self, visit: &mut dyn valuable::Visit) {
        self.redacted.visit(visit);
    }
}

#[cfg(feature = "tracing-valuable")]
impl<T> TracingRedacted for RedactedValuable<T> {}

/// Extension trait for logging redacted values as structured `valuable` data.
///
/// This requires the `tracing-valuable` feature, `RUSTFLAGS="--cfg
/// tracing_unstable"`, and a tracing subscriber that supports the `valuable`
/// crate. The returned wrapper is not itself a `tracing::Value`; bind it first,
/// then pass a reference through `tracing::field::valuable`.
///
/// # Example
///
/// `tracing::field::valuable` is hidden by upstream `tracing` unless the crate
/// is compiled with `RUSTFLAGS="--cfg tracing_unstable"`, so this example cannot
/// be compiled by ordinary doctest runs.
///
/// ```ignore
/// use redactable::{Secret, Sensitive};
/// use redactable::tracing::TracingValuableExt;
///
/// #[derive(Clone, Sensitive, valuable::Valuable)]
/// struct User {
///     username: String,
///     #[sensitive(Secret)]
///     password: String,
/// }
///
/// let user = User { username: "alice".into(), password: "secret".into() };
///
/// let redacted = user.tracing_redacted_valuable();
/// tracing::info!(user = tracing::field::valuable(&redacted));
/// ```
#[cfg(feature = "tracing-valuable")]
pub trait TracingValuableExt {
    /// The redacted type that will be wrapped in `RedactedValuable`.
    type Redacted: valuable::Valuable;

    /// Redacts the value and wraps it for structured tracing output.
    ///
    /// The returned `RedactedValuable` implements `valuable::Valuable`, allowing
    /// tracing subscribers to inspect the redacted structure when passed through
    /// `tracing::field::valuable(&binding)` under `tracing_unstable`.
    fn tracing_redacted_valuable(&self) -> RedactedValuable<Self::Redacted>;
}

#[cfg(feature = "tracing-valuable")]
impl<T> TracingValuableExt for T
where
    T: Redactable + Clone + valuable::Valuable,
{
    type Redacted = T;

    fn tracing_redacted_valuable(&self) -> RedactedValuable<Self::Redacted> {
        RedactedValuable::new(self.clone().redact())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock type for testing TracingRedactedExt
    struct MockRedactable {
        value: String,
    }

    impl ToRedactedOutput for MockRedactable {
        fn to_redacted_output(&self) -> RedactedOutput {
            RedactedOutput::Text(format!("[REDACTED:{}]", self.value.len()))
        }
    }

    #[test]
    fn tracing_redacted_converts_to_display_string() {
        let mock = MockRedactable {
            value: "secret".into(),
        };
        let display_value = mock.tracing_redacted();
        // DisplayValue wraps the string - we can't easily inspect it,
        // but we can verify it was created without panicking
        let _ = format!("{display_value:?}");
    }

    #[test]
    fn tracing_redacted_handles_empty_value() {
        let mock = MockRedactable {
            value: String::new(),
        };
        let display_value = mock.tracing_redacted();
        let _ = format!("{display_value:?}");
    }

    #[derive(Clone, Debug)]
    struct MockStructuralRedactable {
        password: String,
    }

    impl crate::redaction::RedactableWithMapper for MockStructuralRedactable {
        fn redact_with<M: crate::redaction::RedactableMapper>(self, _mapper: &M) -> Self {
            Self {
                password: "[REDACTED]".to_string(),
            }
        }
    }

    impl Redactable for MockStructuralRedactable {}

    #[test]
    fn tracing_redacted_debug_wraps_redacted_clone() {
        let mock = MockStructuralRedactable {
            password: "secret".into(),
        };

        assert_eq!(mock.password, "secret");
        let debug_value = mock.tracing_redacted_debug();
        let output = format!("{debug_value:?}");

        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains("secret"));
    }

    #[cfg(feature = "tracing-valuable")]
    mod valuable_tests {
        use super::*;
        use crate::redaction::{RedactableMapper, RedactableWithMapper};

        // Mock type that implements both Redactable and Valuable
        #[derive(Clone, Debug, valuable::Valuable)]
        struct MockValuableRedactable {
            username: String,
            password: String,
        }

        impl RedactableWithMapper for MockValuableRedactable {
            fn redact_with<M: RedactableMapper>(self, _mapper: &M) -> Self {
                // Simple mock: always redact password
                Self {
                    username: self.username,
                    password: "[REDACTED]".to_string(),
                }
            }
        }

        // Manual machinery impls must also declare certification explicitly.
        impl Redactable for MockValuableRedactable {}

        #[test]
        fn tracing_redacted_valuable_creates_wrapper() {
            let mock = MockValuableRedactable {
                username: "alice".into(),
                password: "secret".into(),
            };
            let valuable = mock.tracing_redacted_valuable();

            // Verify the inner value was redacted
            assert_eq!(valuable.inner().username, "alice");
            assert_eq!(valuable.inner().password, "[REDACTED]");
        }

        #[test]
        fn redacted_valuable_implements_valuable() {
            let mock = MockValuableRedactable {
                username: "alice".into(),
                password: "secret".into(),
            };
            let valuable_wrapper = mock.tracing_redacted_valuable();

            // Verify it implements Valuable by calling as_value
            let _ = valuable::Valuable::as_value(&valuable_wrapper);
        }
    }
}
