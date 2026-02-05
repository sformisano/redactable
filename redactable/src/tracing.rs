//! Adapters for emitting redacted values through `tracing`.
//!
//! This module provides two approaches for logging redacted values:
//!
//! - **`TracingRedactedExt`**: Logs redacted values as display strings. Works with any
//!   tracing subscriber but loses structure.
//!
//! - **`TracingValuableExt`** (requires `tracing-valuable` feature): Logs redacted values
//!   as structured data via the `valuable` crate. Subscribers that support `valuable` can
//!   traverse fields as nested, typed structures.
//!
//! # Example
//!
//! ```ignore
//! use redactable::tracing::{TracingRedactedExt, TracingValuableExt};
//!
//! // As display string (always available with "tracing" feature)
//! tracing::info!(user = %user.tracing_redacted());
//!
//! // As structured valuable (requires "tracing-valuable" feature)
//! tracing::info!(user = user.tracing_redacted_valuable());
//! ```

use std::fmt;

#[cfg(feature = "json")]
use serde::Serialize;
use tracing::field::{DisplayValue, display};

use crate::{
    policy::RedactionPolicy,
    redaction::{
        NotSensitiveDebug, NotSensitiveDisplay, NotSensitiveJson, Redactable, RedactableWithPolicy,
        RedactedJsonRef, RedactedOutput, RedactedOutputRef, SensitiveValue, ToRedactedOutput,
    },
};

/// Marker trait for types whose `tracing` integration always emits redacted output.
///
/// This marker indicates that the type will produce redacted output when used
/// with tracing (via `TracingRedactedExt` or `TracingValuableExt`).
///
/// This trait is implemented only for sink adapters and wrappers that redact
/// before logging. It is not a blanket impl for raw types.
pub trait TracingRedacted {}

/// Extension trait for logging redacted values as display strings.
///
/// This works with any tracing subscriber but the output is a flat string,
/// not structured data. For structured output, see `TracingValuableExt`.
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

impl<T, P> TracingRedacted for SensitiveValue<T, P>
where
    T: RedactableWithPolicy<P>,
    P: RedactionPolicy,
{
}

impl<T> TracingRedacted for NotSensitiveDisplay<'_, T> where T: fmt::Display + ?Sized {}

impl<T> TracingRedacted for NotSensitiveDebug<'_, T> where T: fmt::Debug + ?Sized {}

impl<T> TracingRedacted for RedactedOutputRef<'_, T> where T: Redactable + Clone + fmt::Debug {}

#[cfg(feature = "json")]
impl<T> TracingRedacted for NotSensitiveJson<'_, T> where T: Serialize + ?Sized {}

#[cfg(feature = "json")]
impl<T> TracingRedacted for RedactedJsonRef<'_, T> where T: Redactable + Clone + Serialize {}

/// A redacted value that implements `valuable::Valuable` for structured tracing output.
///
/// This wrapper holds the redacted form of a value and exposes it via the `valuable`
/// crate's inspection traits, allowing tracing subscribers to traverse fields as
/// nested, typed structures.
#[cfg(feature = "tracing-valuable")]
#[derive(Clone, Debug)]
pub struct RedactedValuable<T> {
    redacted: T,
}

#[cfg(feature = "tracing-valuable")]
impl<T> RedactedValuable<T> {
    /// Creates a new `RedactedValuable` from an already-redacted value.
    pub fn new(redacted: T) -> Self {
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
/// This requires the `tracing-valuable` feature and a tracing subscriber that
/// supports the `valuable` crate. The redacted value's fields can be traversed
/// as nested, typed structures in telemetry systems.
///
/// # Example
///
/// ```ignore
/// use redactable::tracing::TracingValuableExt;
///
/// #[derive(Clone, Sensitive, valuable::Valuable)]
/// struct User {
///     username: String,
///     #[sensitive(Default)]
///     password: String,
/// }
///
/// let user = User { username: "alice".into(), password: "secret".into() };
///
/// // Log as structured data - subscriber can traverse user.username, user.password
/// tracing::info!(user = user.tracing_redacted_valuable());
/// ```
#[cfg(feature = "tracing-valuable")]
pub trait TracingValuableExt {
    /// The redacted type that will be wrapped in `RedactedValuable`.
    type Redacted: valuable::Valuable;

    /// Redacts the value and wraps it for structured tracing output.
    ///
    /// The returned `RedactedValuable` implements `valuable::Valuable`, allowing
    /// tracing subscribers to inspect the redacted structure.
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

    #[cfg(feature = "tracing-valuable")]
    mod valuable_tests {
        use super::*;
        use crate::redaction::{RedactableContainer, RedactableMapper};

        // Mock type that implements both Redactable and Valuable
        #[derive(Clone, Debug, valuable::Valuable)]
        struct MockValuableRedactable {
            username: String,
            password: String,
        }

        impl RedactableContainer for MockValuableRedactable {
            fn redact_with<M: RedactableMapper>(self, _mapper: &M) -> Self {
                // Simple mock: always redact password
                Self {
                    username: self.username,
                    password: "[REDACTED]".to_string(),
                }
            }
        }

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
