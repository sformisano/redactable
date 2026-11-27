//! Checked logging for `log`, `slog`, and `tracing`.
//!
//! Import [`info!`](crate::info!), [`warn!`](crate::warn!), [`error!`](crate::error!),
//! [`debug!`](crate::debug!), or [`trace!`](crate::trace!). The `log` feature
//! uses the application's installed `log` logger. To use tracing or a slog
//! logger, call [`set_sink`] once at startup.
//!
//! ```
//! use redactable::{info, Secret, SensitiveValue};
//!
//! let token = SensitiveValue::<_, Secret>::from(String::from("example-token"));
//! info!("started");
//! info!(token; "credential checked");
//! info!("credential checked for {}", token);
//! ```
//!
//! Named fields and format arguments require [`crate::ToRedacted`]. A plain
//! field selects JSON. Both `key:%` and `key:?` select the declared text.
//! Message arguments format that text, with standard Rust string formatting.
//! Supply named arguments explicitly, as in `info!("checked {who}", who = user)`.
//! Import [`crate::BypassRedactionExt`] to publish an ordinary value explicitly
//! with `.bypass_display()` or `.bypass_json()`. For Debug output, use
//! [`crate::BypassDebugRedaction`].
//!
//! Each field needs a unique name. The name `message` is reserved for the
//! event text. For a single event with a contextual destination, use
//! `info!(sink: &request_sink, user; "signed in")`.
//!
//! ```compile_fail
//! use redactable::info;
//!
//! let raw = String::from("example-token");
//! info!("credential checked for {}", raw);
//! ```
//!
//! ```compile_fail
//! use redactable::info;
//!
//! info!(message = (); "credential checked");
//! ```

mod message;
mod route;

#[doc(hidden)]
pub use route::{__default_route, Route};
pub use route::{SetSinkError, Sink, set_sink};

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
    ($level:ident, sink: $sink:expr, $($input:tt)+) => {{
        let selected_sink = &$sink;
        $crate::__redactable_event!(@parse ($level, $crate::logging::Sink::route(selected_sink)) $($input)+)
    }};
    ($level:ident, $($input:tt)+) => {
        $crate::__redactable_event!(@parse ($level, $crate::logging::__default_route()) $($input)+)
    };
    (@parse ($level:ident, $route:expr) $fmt:literal $($args:tt)*) => {
        $crate::__redactable_event!(@modes [] ($level, $route, [], $fmt $($args)*))
    };
    (@parse ($level:ident, $route:expr) $($key:ident $(:$mode:tt)? $(= $value:expr)?),+ $(,)?; $fmt:literal $($args:tt)*) => {{
        $crate::__redactable_event!(@keys [$($key),+] $);
        $crate::__redactable_event!(
            @modes [$($($mode)?)+] ($level, $route, [$($key [$($mode)?] ($crate::__redactable_event!(@value $key $(= $value)?))),+], $fmt $($args)*)
        )
    }};
    (@value $key:ident) => { $key };
    (@value $key:ident = $value:expr) => { $value };
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
    (@modes [] ($level:ident, $route:expr, $fields:tt, $fmt:literal $($args:tt)*)) => {{
        const _: &::core::primitive::str = $fmt;
        // Keep message operands inside the native event macro's level check.
        $crate::__redactable_event!(@emit ($level, $route, $fields) $crate::__redactable_message!($fmt $($args)*))
    }};
    (@emit ($level:ident, $route:expr, $fields:tt) $message:expr) => {
        match $route {
            $crate::logging::Route::Log => {
                $crate::logging::__emit_log!($level, (), $fields, $message)
            }
            $crate::logging::Route::Tracing => {
                $crate::logging::__emit_tracing!($level, (), $fields, $message)
            }
            $crate::logging::Route::Slog(logger) => {
                $crate::logging::__emit_slog!($level, logger, $fields, $message)
            }
            $crate::logging::Route::Disabled => {}
        }
    };
}

/// Logs a checked event at the error level through the application's selected backend.
#[macro_export]
macro_rules! error {
    ($($args:tt)*) => { $crate::__redactable_event!(Error, $($args)*) };
}

/// Logs a checked event at the warn level through the application's selected backend.
#[macro_export]
macro_rules! warn {
    ($($args:tt)*) => { $crate::__redactable_event!(Warn, $($args)*) };
}

/// Logs a checked event at the info level through the application's selected backend.
#[macro_export]
macro_rules! info {
    ($($args:tt)*) => { $crate::__redactable_event!(Info, $($args)*) };
}

/// Logs a checked event at the debug level through the application's selected backend.
#[macro_export]
macro_rules! debug {
    ($($args:tt)*) => { $crate::__redactable_event!(Debug, $($args)*) };
}

/// Logs a checked event at the trace level through the application's selected backend.
#[macro_export]
macro_rules! trace {
    ($($args:tt)*) => { $crate::__redactable_event!(Trace, $($args)*) };
}
