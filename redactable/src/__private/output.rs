//! Output wrappers that preserve nested borrow conflicts during policy
//! application and formatting.

use std::cell::RefCell;

// Kept in scope for the intra-doc link on `PolicyFormattingOutput`.
use crate::RedactableWithFormatter;
#[allow(unused_imports)]
use crate::redaction::PolicyApplicableRef;

/// Legacy borrow-safe `RefCell` policy output retained for API compatibility.
pub enum PolicyRefCellOutput<T> {
    /// The source was borrowable and contains the original output shape.
    Value(RefCell<T>),
    /// The source was mutably borrowed; no value or error is retained.
    Borrowed,
}

impl<T: RedactableWithFormatter> RedactableWithFormatter for PolicyRefCellOutput<T> {
    fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Value(value) => value.fmt_redacted(f),
            Self::Borrowed => f.write_str("<borrowed>"),
        }
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for PolicyRefCellOutput<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Value(value) => std::fmt::Debug::fmt(value, f),
            Self::Borrowed => f.write_str("<borrowed>"),
        }
    }
}

/// Formatting-only result of applying a reference policy.
///
/// This keeps borrow-conflict handling out of [`PolicyApplicableRef::Output`],
/// preserving that public associated-type contract for downstream callers.
pub enum PolicyFormattingOutput<T> {
    /// The policy was applied and produced the normal output shape.
    Value(T),
    /// The source was mutably borrowed; no value or error is retained.
    Borrowed,
}

impl<T> PolicyFormattingOutput<T> {
    /// Transforms a successful formatting value while preserving a borrow conflict.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> PolicyFormattingOutput<U> {
        match self {
            Self::Value(value) => PolicyFormattingOutput::Value(f(value)),
            Self::Borrowed => PolicyFormattingOutput::Borrowed,
        }
    }
}

impl<T: RedactableWithFormatter> RedactableWithFormatter for PolicyFormattingOutput<T> {
    fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Value(value) => value.fmt_redacted(f),
            Self::Borrowed => f.write_str("<borrowed>"),
        }
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for PolicyFormattingOutput<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Value(value) => std::fmt::Debug::fmt(value, f),
            Self::Borrowed => f.write_str("<borrowed>"),
        }
    }
}
