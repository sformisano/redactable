//! Checked event logging through an application-selected [`Sink`].
//!
//! Pass the sink to [`crate::error!`], [`crate::warn!`], [`crate::info!`],
//! [`crate::debug!`], or [`crate::trace!`]. Each named field requires
//! [`crate::ToRedacted`]. A plain field selects the structured view.
//! Both `:%` and `:?` select the producer's [redacted text](crate::RedactedValue::text).
//! Messages are fixed string literals. Use `{{` and `}}` to emit literal braces.
//! Each field name must be unique, including its raw identifier spelling.
//! The event text reserves the field name `message`, including its raw
//! identifier spelling `r#message`.
//!
//! ```
//! use redactable::{info, logging::Sink, Secret, SensitiveValue};
//!
//! fn checked(sink: &Sink) {
//!     let token = SensitiveValue::<_, Secret>::from(String::from("example-token"));
//!     info!(sink, token:% = &token; "credential checked");
//! }
//! ```
//!
//! Use [`crate::BypassDisplayRedaction`], [`crate::BypassDebugRedaction`],
//! or [`crate::BypassJsonRedaction`] to declare the complete output public.
//!
//! ```compile_fail
//! use redactable::{info, logging::Sink};
//!
//! fn unchecked(sink: &Sink, raw: String) {
//!     info!(sink, token = raw; "credential checked");
//! }
//! ```
//!
//! ```compile_fail
//! use redactable::{info, logging::Sink};
//!
//! fn event(sink: &Sink) {
//!     info!(sink, message = (); "credential checked");
//! }
//! ```

#[cfg(feature = "slog")]
use ::slog::Logger as SlogLogger;
#[cfg(not(feature = "slog"))]
use std::convert::Infallible as SlogLogger;

/// The backend used by a checked logging macro.
///
/// Cargo features make the corresponding variants available. The application
/// chooses a variant and configures the backend.
/// The macro evaluates its sink once. The selected backend's native event
/// macro controls when it evaluates fields.
#[derive(Clone, Debug)]
#[non_exhaustive]
#[allow(missing_copy_implementations)] // The slog variant owns its logger.
pub enum Sink {
    /// The application's global `log` logger.
    #[cfg(feature = "log")]
    Log,
    /// The active `tracing` subscriber.
    #[cfg(feature = "tracing")]
    Tracing,
    /// A `slog` logger with its configured drain and context.
    #[cfg(feature = "slog")]
    Slog(SlogLogger),
}

// All arms exist in the consumer macro expansion, regardless of which
// features Cargo enabled on Redactable. Only enabled sinks produce a route.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub enum Route<'a> {
    Log,
    Tracing,
    Slog(&'a SlogLogger),
}

impl Sink {
    #[doc(hidden)]
    pub fn route(&self) -> Route<'_> {
        match self {
            #[cfg(feature = "log")]
            Self::Log => Route::Log,
            #[cfg(feature = "tracing")]
            Self::Tracing => Route::Tracing,
            #[cfg(feature = "slog")]
            Self::Slog(logger) => Route::Slog(logger),
        }
    }
}

#[doc(hidden)]
pub fn __text(value: &crate::RedactedValue) -> std::borrow::Cow<'_, str> {
    value.text_view()
}

#[doc(hidden)]
#[macro_export]
macro_rules! __redactable_field {
    (json $value:expr) => {
        ::core::convert::AsRef::<$crate::RedactedValue>::as_ref(
            &$crate::ToRedacted::to_redacted_cow(&$value),
        )
    };
    (text $value:expr) => {
        ::core::convert::AsRef::<::core::primitive::str>::as_ref(
            &$crate::logging::__text($crate::__redactable_field!(json $value)),
        )
    };
    ([] $value:expr) => { $crate::__redactable_field!(json $value) };
    ([%] $value:expr) => { $crate::__redactable_field!(text $value) };
    ([?] $value:expr) => { $crate::__redactable_field!(text $value) };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __redactable_disabled_sink {
    ($level:ident, $destination:expr, $fields:tt, $message:expr) => {{
        let _ = $destination;
        ::core::unreachable!("disabled Redactable logging backend")
    }};
}

#[doc(hidden)]
#[cfg(not(feature = "log"))]
pub use crate::__redactable_disabled_sink as __emit_log;
#[doc(hidden)]
#[cfg(not(feature = "slog"))]
pub use crate::__redactable_disabled_sink as __emit_slog;
#[doc(hidden)]
#[cfg(not(feature = "tracing"))]
pub use crate::__redactable_disabled_sink as __emit_tracing;
#[doc(hidden)]
#[cfg(feature = "log")]
pub use crate::__redactable_emit_log as __emit_log;
#[doc(hidden)]
#[cfg(feature = "slog")]
pub use crate::__redactable_emit_slog as __emit_slog;
#[doc(hidden)]
#[cfg(feature = "tracing")]
pub use crate::__redactable_emit_tracing as __emit_tracing;

#[doc(hidden)]
#[macro_export]
macro_rules! __redactable_event {
    ($level:ident, $sink:expr, $message:literal $(,)?) => {
        $crate::__redactable_event!(@modes [] ($level, $sink, [], $message))
    };
    ($level:ident, $sink:expr, $($key:ident $(:$mode:tt)? = $value:expr),+ $(,)?; $message:literal $(,)?) => {{
        $crate::__redactable_event!(@keys [$($key),+] $);
        $crate::__redactable_event!(
            @modes [$($($mode)?)+] ($level, $sink, [$($key [$($mode)?] ($value)),+], $message)
        )
    }};
    (@keys [$($key:ident),+] $dollar:tt) => {
        $($crate::__redactable_event!(@key $key);)+
        // Rust rejects repeated macro binding names and accepts keyword identifiers.
        // The forwarded dollar sign introduces a binding for each supplied key.
        #[allow(unused_macros)]
        macro_rules! __redactable_unique_field_names { ($($dollar $key:tt),+) => {}; }
    };
    (@key message) => {
        ::core::compile_error!("the field name `message` is reserved for the event message")
    };
    (@key r#message) => { $crate::__redactable_event!(@key message) };
    (@key $other:ident) => {};
    (@modes [% $($tail:tt)*] $event:tt) => { $crate::__redactable_event!(@modes [$($tail)*] $event) };
    (@modes [? $($tail:tt)*] $event:tt) => { $crate::__redactable_event!(@modes [$($tail)*] $event) };
    (@modes [$other:tt $($tail:tt)*] $event:tt) => {
        ::core::compile_error!("checked fields support only the :% and :? text selectors")
    };
    (@modes [] ($level:ident, $sink:expr, $fields:tt, $message:literal)) => {{
        const _: &::core::primitive::str = $message;
        let selected_sink = &$sink;
        // A format string expanded by concat! cannot capture caller variables.
        let message = const { ::core::format_args!(::core::concat!($message)) };
        match $crate::logging::Sink::route(selected_sink) {
            $crate::logging::Route::Log => {
                $crate::logging::__emit_log!($level, (), $fields, message)
            }
            $crate::logging::Route::Tracing => {
                $crate::logging::__emit_tracing!($level, (), $fields, message)
            }
            $crate::logging::Route::Slog(logger) => {
                $crate::logging::__emit_slog!($level, logger, $fields, message)
            }
        }
    }};
}

/// Logs a checked event at the error level through a [`Sink`](crate::logging::Sink).
#[macro_export]
macro_rules! error {
    ($($args:tt)*) => { $crate::__redactable_event!(Error, $($args)*) };
}

/// Logs a checked event at the warn level through a [`Sink`](crate::logging::Sink).
#[macro_export]
macro_rules! warn {
    ($($args:tt)*) => { $crate::__redactable_event!(Warn, $($args)*) };
}

/// Logs a checked event at the info level through a [`Sink`](crate::logging::Sink).
#[macro_export]
macro_rules! info {
    ($($args:tt)*) => { $crate::__redactable_event!(Info, $($args)*) };
}

/// Logs a checked event at the debug level through a [`Sink`](crate::logging::Sink).
#[macro_export]
macro_rules! debug {
    ($($args:tt)*) => { $crate::__redactable_event!(Debug, $($args)*) };
}

/// Logs a checked event at the trace level through a [`Sink`](crate::logging::Sink).
#[macro_export]
macro_rules! trace {
    ($($args:tt)*) => { $crate::__redactable_event!(Trace, $($args)*) };
}
