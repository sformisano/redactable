//! Structured redacted fields for the `log` crate.
//!
//! The application chooses and initializes a backend that serializes
//! `log` key-value fields through Serde. Use [`crate::logging::Sink::Log`]
//! with Redactable's checked logging macros.

use ::log::kv::{ToValue, Value};

use crate::{RedactedValue, ToRedacted};

// Resolve the exact log dependency used by this crate in macro expansions.
#[doc(hidden)]
pub use ::log::{Level as __Level, log as __log};

#[doc(hidden)]
#[macro_export]
macro_rules! __redactable_emit_log {
    ($level:ident, $destination:expr, [], $message:expr) => {
        $crate::log::__log!($crate::log::__Level::$level, "{}", $message)
    };
    ($level:ident, $destination:expr, [$($key:ident [$($mode:tt)?] ($value:expr)),+], $message:expr) => {
        $crate::log::__log!(
            $crate::log::__Level::$level,
            $($key = $crate::__redactable_field!([$($mode)?] $value)),+; "{}", $message
        )
    };
}

/// Extension trait for logging a producer's redacted JSON through `log`.
///
/// ```
/// use redactable::{LogRedactedExt, Secret, SensitiveValue};
///
/// let token = SensitiveValue::<_, Secret>::from(String::from("example-token"));
/// let field = token.log_redacted_json();
/// assert_eq!(
///     serde_json::to_value(&field).unwrap(),
///     serde_json::json!({"message": "[REDACTED]"}),
/// );
/// log::info!(token = &field; "credential checked");
/// ```
pub trait LogRedactedExt: ToRedacted {
    /// Runs the producer once and returns its owned [`RedactedValue`].
    ///
    /// A `log` field borrows this value and serializes its JSON representation.
    /// Pass an existing value directly with `log::info!(user = &value; "signed in")`.
    ///
    /// # Panics
    ///
    /// This method inherits the producer's panics, including those from cloning
    /// a structural producer. See [`ToRedacted::to_redacted`].
    #[must_use]
    fn log_redacted_json(&self) -> RedactedValue {
        self.to_redacted()
    }
}

impl<T: ToRedacted + ?Sized> LogRedactedExt for T {}

impl ToValue for RedactedValue {
    fn to_value(&self) -> Value<'_> {
        Value::from_serde(self)
    }
}
