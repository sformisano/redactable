//! Adapters for emitting redacted values through `tracing`.
//!
//! This module provides three explicit tracing paths:
//!
//! - **[`TracingRedactedDebugExt`]**: redacts a structural [`Redactable`] value
//!   before handing its `Debug` form to tracing.
//!
//! - **[`TracingRedactedExt`]**: logs `ToRedacted` values as display strings.
//!   Works with any tracing subscriber but loses structure.
//!
//! - **`TracingValuableExt`** (requires the `tracing-valuable` feature and
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
//!     #[not_sensitive]
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

use std::fmt::{Debug, Display};

#[cfg(feature = "tracing-valuable")]
use valuable::{Valuable, Value as ValuableValue, Visit as ValuableVisit};

use serde::Serialize;
use tracing::field::{DebugValue, DisplayValue, debug, display};

use crate::{
    policy::RedactionPolicy,
    redaction::{
        BypassDebugRedaction, BypassDisplayRedaction, BypassJsonRedaction, BypassRedactionMarker,
        Redactable, RedactedValue, SensitiveValue, SensitiveWithPolicy, ToRedacted,
    },
};

/// Marker trait for types whose `tracing` integration always emits logging-safe output.
///
/// Implementors are safe because they either redact their value or represent a
/// value explicitly declared non-sensitive before it reaches tracing (via
/// `TracingRedactedDebugExt`, `TracingRedactedExt`, or `TracingValuableExt`).
///
/// This trait is implemented only for logging-safe adapters and wrappers. It is
/// not a blanket impl for raw types.
///
/// ```compile_fail
/// use redactable::tracing::TracingRedacted;
///
/// fn assert_tracing_redacted<T: TracingRedacted>() {}
///
/// assert_tracing_redacted::<String>();
/// ```
pub trait TracingRedacted {}

/// Extension trait for logging structural redacted values as `Debug` fields.
///
/// This is the plain `tracing` path for types that derive `Sensitive` or
/// otherwise implement [`Redactable`]. The helper clones and redacts the value
/// before it reaches the subscriber, then records the redacted clone through
/// `tracing::field::debug`.
pub trait TracingRedactedDebugExt: Redactable + Clone + Debug {
    /// Redacts the value and wraps the redacted clone for `tracing` debug
    /// recording.
    ///
    /// # Panics
    ///
    /// This method inherits every panic from cloning `Self`. In particular, a
    /// traversed [`std::cell::RefCell`] with a live mutable borrow panics. Use
    /// [`IntoTracingRedactedDebugExt::into_tracing_redacted_debug`] when the
    /// original value does not need to be retained.
    fn tracing_redacted_debug(&self) -> DebugValue<Self>;
}

/// Consuming extension trait for structural Debug fields in `tracing`.
///
/// This adapter redacts the owned value by calling `.redact()` on it instead of cloning it first. It accepts
/// every [`Redactable`] shape, including types using `#[redactable(recursive)]`.
///
/// # Panics
///
/// The adapter does not clone the value before redacting (unlike the borrowed adapters), but a type's own `.redact()` may clone internally: traversal through
/// [`std::sync::Arc`] or [`std::rc::Rc`] must clone the shared referent because
/// other owners may still hold it, and rebuilding a `HashMap` or `HashSet` clones its `BuildHasher` (a custom hasher whose `Clone` panics or has side effects surfaces here). A live [`std::cell::RefCell`] mutable borrow
/// behind an `Arc`/`Rc` therefore still panics. Prefer unique ownership
/// ([`Box`]) for values you log. (`Arc<RefCell<T>>` is `!Send + !Sync` and an
/// anti-pattern regardless.)
pub trait IntoTracingRedactedDebugExt: Redactable + Debug + Sized {
    /// Consumes and redacts the value before handing it to `tracing`.
    #[must_use]
    fn into_tracing_redacted_debug(self) -> DebugValue<Self> {
        debug(self.redact())
    }
}

impl<T> IntoTracingRedactedDebugExt for T where T: Redactable + Debug {}

impl<T> TracingRedactedDebugExt for T
where
    T: Redactable + Clone + Debug,
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
/// `TracingValuableExt`.
pub trait TracingRedactedExt {
    /// Wraps the value for `tracing` logging as a display value.
    ///
    /// The value is redacted and converted to a string representation.
    ///
    /// # Panics
    ///
    /// This method inherits panics from [`ToRedacted`]. Producing a structural
    /// value generated by `Sensitive` or `SensitiveDual` clones `self` first, so
    /// a traversed [`std::cell::RefCell`] with a live mutable borrow panics
    /// here; `SensitiveDisplay` producers format the borrowed value through the
    /// crate's formatter, which renders such a cell as `<borrowed>`, and
    /// `NotSensitiveDisplay` inherits the type's own `Display`.
    fn tracing_redacted(&self) -> DisplayValue<String>;
}

impl<T> TracingRedactedExt for T
where
    T: ToRedacted,
{
    fn tracing_redacted(&self) -> DisplayValue<String> {
        display(self.to_redacted().text())
    }
}

impl TracingRedacted for RedactedValue {}

impl<T, P> TracingRedacted for SensitiveValue<T, P>
where
    T: SensitiveWithPolicy<P>,
    P: RedactionPolicy,
{
}

impl<T> TracingRedacted for BypassDisplayRedaction<T> where T: Display {}

impl<T> TracingRedacted for BypassDebugRedaction<T> where T: Debug {}

impl<T> TracingRedacted for BypassRedactionMarker<T> {}

impl<T> TracingRedacted for BypassJsonRedaction<'_, T> where T: Serialize + ?Sized {}

/// A redacted value that implements `valuable::Valuable` for structured tracing output.
///
/// This wrapper is constructed by [`TracingValuableExt::tracing_redacted_valuable`]
/// so callers cannot build structured tracing payloads without first applying
/// redaction. Pass a reference to the wrapper through `tracing::field::valuable`
/// when compiling with `RUSTFLAGS="--cfg tracing_unstable"`.
/// Deliberately NOT `Clone`. Cloning the wrapper would hand out a second handle
/// to the same redacted value; if that value has shared interior mutability
/// (e.g. an `Arc`/`Rc` over a `Cell`/`Mutex`), a caller could clone the wrapper,
/// mutate the shared inner through the clone to insert a *fresh* secret, and
/// have the original wrapper log it. Without `Clone`, the only way to reach the
/// inner value is the consuming [`Self::into_inner`], which leaves no original
/// wrapper behind to log.
#[cfg(feature = "tracing-valuable")]
#[derive(Debug)]
pub struct TracingRedactedValue<T> {
    redacted: T,
}

#[cfg(feature = "tracing-valuable")]
impl<T> TracingRedactedValue<T> {
    /// Creates a new `TracingRedactedValue` from an already-redacted value.
    pub(crate) fn new(redacted: T) -> Self {
        Self { redacted }
    }

    /// Consumes the wrapper and returns the redacted inner value.
    ///
    /// This is deliberately consuming rather than a borrowing `inner(&self)`.
    /// The original secret is already gone by the time a `TracingRedactedValue`
    /// exists, but a shared reference to an interior-mutable inner value would
    /// let a caller write a *fresh* secret into the wrapper after redaction and
    /// before it is logged. Taking `self` closes that window.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.redacted
    }
}

#[cfg(feature = "tracing-valuable")]
impl<T: Valuable> Valuable for TracingRedactedValue<T> {
    fn as_value(&self) -> ValuableValue<'_> {
        self.redacted.as_value()
    }

    fn visit(&self, visit: &mut dyn ValuableVisit) {
        self.redacted.visit(visit);
    }
}

#[cfg(feature = "tracing-valuable")]
impl<T> TracingRedacted for TracingRedactedValue<T> {}

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
/// #[derive(Clone, Sensitive, serde::Serialize, valuable::Valuable)]
/// struct User {
///     #[not_sensitive]
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
    /// The redacted type that will be wrapped in `TracingRedactedValue`.
    type Redacted: Valuable;

    /// Redacts the value and wraps it for structured tracing output.
    ///
    /// The returned `TracingRedactedValue` implements `valuable::Valuable`, allowing
    /// tracing subscribers to inspect the redacted structure when passed through
    /// `tracing::field::valuable(&binding)` under `tracing_unstable`.
    ///
    /// # Panics
    ///
    /// This method inherits every panic from cloning `Self`. In particular, a
    /// traversed [`std::cell::RefCell`] with a live mutable borrow panics. Use
    /// [`IntoTracingRedactedValuableExt::into_tracing_redacted_valuable`] when
    /// the original value does not need to be retained.
    fn tracing_redacted_valuable(&self) -> TracingRedactedValue<Self::Redacted>;
}

/// Consuming extension trait for structured `valuable` tracing output.
///
/// This adapter redacts the owned value by calling `.redact()` on it instead of cloning it first. It accepts
/// every [`Redactable`] shape, including types using `#[redactable(recursive)]`.
///
/// # Panics
///
/// The adapter does not clone the value before redacting (unlike the borrowed adapters), but a type's own `.redact()` may clone internally: traversal through
/// [`std::sync::Arc`] or [`std::rc::Rc`] must clone the shared referent because
/// other owners may still hold it, and rebuilding a `HashMap` or `HashSet` clones its `BuildHasher` (a custom hasher whose `Clone` panics or has side effects surfaces here). A live [`std::cell::RefCell`] mutable borrow
/// behind an `Arc`/`Rc` therefore still panics. Prefer unique ownership
/// ([`Box`]) for values you log. (`Arc<RefCell<T>>` is `!Send + !Sync` and an
/// anti-pattern regardless.)
#[cfg(feature = "tracing-valuable")]
pub trait IntoTracingRedactedValuableExt: Redactable + Valuable + Sized {
    /// Consumes and redacts the value before wrapping it for `valuable` output.
    #[must_use]
    fn into_tracing_redacted_valuable(self) -> TracingRedactedValue<Self> {
        TracingRedactedValue::new(self.redact())
    }
}

#[cfg(feature = "tracing-valuable")]
impl<T> IntoTracingRedactedValuableExt for T where T: Redactable + Valuable {}

#[cfg(feature = "tracing-valuable")]
impl<T> TracingValuableExt for T
where
    T: Redactable + Clone + Valuable,
{
    type Redacted = T;

    fn tracing_redacted_valuable(&self) -> TracingRedactedValue<Self::Redacted> {
        TracingRedactedValue::new(self.clone().redact())
    }
}

#[cfg(test)]
mod tests {
    use super::{TracingRedactedDebugExt, TracingRedactedExt};
    use crate::redaction::{
        BypassTextRedaction, Redactable, RedactableMapper, RedactableWithMapper, RedactedValue,
        ToRedacted,
    };

    // Mock type for testing TracingRedactedExt
    struct MockRedactable {
        value: String,
    }

    impl ToRedacted for MockRedactable {
        fn to_redacted(&self) -> RedactedValue {
            BypassTextRedaction(format!("[REDACTED:{}]", self.value.len())).to_redacted()
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

    impl RedactableWithMapper for MockStructuralRedactable {
        fn redact_with<M: RedactableMapper>(self, _mapper: &M) -> Self {
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
        use crate::redaction::{Redactable, RedactableMapper, RedactableWithMapper};
        use crate::tracing::TracingValuableExt;
        use valuable::Valuable;

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
            let inner = valuable.into_inner();
            assert_eq!(inner.username, "alice");
            assert_eq!(inner.password, "[REDACTED]");
        }

        #[test]
        fn redacted_valuable_implements_valuable() {
            let mock = MockValuableRedactable {
                username: "alice".into(),
                password: "secret".into(),
            };
            let valuable_wrapper = mock.tracing_redacted_valuable();

            // Verify it implements Valuable by calling as_value
            let _ = Valuable::as_value(&valuable_wrapper);
        }
    }
}
