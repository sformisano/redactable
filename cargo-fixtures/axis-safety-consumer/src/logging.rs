//! Routing from Axis's `crates/framework/public/application/src/macros/logging.rs`
//! and `observability/logger.rs`, revision 14417ae77286e45a7d4dbbd8e674a9a6cc091397.

use redactable::{Redactable, RedactedOutputView, ToRedactedOutput};
use serde::Serialize;
use serde_json::Value;

pub fn field_redacted<T: Redactable + Serialize + Clone>(value: &T) -> Value {
    // Axis's serializer also returns null on failure. The bounded samples use
    // ordinary Serde objects, strings, booleans and options.
    serde_json::to_value(value.clone().redact()).unwrap_or(Value::Null)
}

pub fn field_typed<T: ToRedactedOutput + ?Sized>(value: &T) -> Value {
    let output = value.to_redacted_output();
    match output.view() {
        RedactedOutputView::Text(text) => Value::String(text.to_owned()),
        RedactedOutputView::Json(json) => json.clone(),
        _ => Value::String(format!("{output:?}")),
    }
}

pub fn field_text<T: ToRedactedOutput + ?Sized>(value: &T) -> Value {
    let output = value.to_redacted_output();
    Value::String(match output.view() {
        RedactedOutputView::Text(text) => text.to_owned(),
        RedactedOutputView::Json(json) => json.to_string(),
        _ => format!("{output:?}"),
    })
}

// Axis's audit/display.rs deliberately accepts only the selected Text form.
pub fn audit_display<T: ToRedactedOutput + ?Sized>(value: &T) -> String {
    let output = value.to_redacted_output();
    match output.view() {
        RedactedOutputView::Text(text) => text.to_owned(),
        _ => "<redaction-unavailable>".to_owned(),
    }
}

// This recursive routing preserves Axis's syntax and borrowing at each field.
// Qualified paths are macro hygiene: resolution happens at the invocation site.
macro_rules! axis_fields {
    (@acc [$($acc:expr),*]) => {
        serde_json::Value::Object([$($acc),*].into_iter().collect())
    };
    (@acc [$($acc:expr),*] $key:ident = %$value:expr, $($rest:tt)*) => {
        $crate::logging::axis_fields!(@acc [$($acc,)*
            (stringify!($key).to_owned(), $crate::logging::field_text(&$value))] $($rest)*)
    };
    (@acc [$($acc:expr),*] $key:ident = ?$value:expr, $($rest:tt)*) => {
        $crate::logging::axis_fields!(@acc [$($acc,)*
            (stringify!($key).to_owned(), $crate::logging::field_text(&$value))] $($rest)*)
    };
    (@acc [$($acc:expr),*] $key:ident = @$value:expr, $($rest:tt)*) => {
        $crate::logging::axis_fields!(@acc [$($acc,)*
            (stringify!($key).to_owned(), $crate::logging::field_typed(&$value))] $($rest)*)
    };
    (@acc [$($acc:expr),*] $key:ident = $value:expr, $($rest:tt)*) => {
        $crate::logging::axis_fields!(@acc [$($acc,)*
            (stringify!($key).to_owned(), $crate::logging::field_redacted(&$value))] $($rest)*)
    };
    (@acc [$($acc:expr),*] $key:ident = %$value:expr) => {
        $crate::logging::axis_fields!(@acc [$($acc),*] $key = %$value,)
    };
    (@acc [$($acc:expr),*] $key:ident = ?$value:expr) => {
        $crate::logging::axis_fields!(@acc [$($acc),*] $key = ?$value,)
    };
    (@acc [$($acc:expr),*] $key:ident = @$value:expr) => {
        $crate::logging::axis_fields!(@acc [$($acc),*] $key = @$value,)
    };
    (@acc [$($acc:expr),*] $key:ident = $value:expr) => {
        $crate::logging::axis_fields!(@acc [$($acc),*] $key = $value,)
    };
    ($($fields:tt)*) => {
        $crate::logging::axis_fields!(@acc [] $($fields)*)
    };
}

pub(crate) use axis_fields;
