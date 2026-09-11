//! Fixture types for comparing derive-generated `Debug` across build modes.
//!
//! This crate is compiled as a dependency, so `cfg!(test)` is false inside it.
//! Integration tests compare these dependency-built types with types defined
//! inside a consumer test. Both must retain the same production redaction,
//! including when the `testing` feature is enabled.

use redactable::{
    Email, Redactable, RedactableMapper, RedactableWithMapper, Secret, Sensitive, SensitiveDisplay,
    SensitiveDual, Token,
};
use std::fmt::Display;

/// Exact README tracing fixture with production-compiled generated `Debug`.
#[derive(Clone, Sensitive, serde::Serialize)]
pub struct AuthEvent {
    #[sensitive(Token)]
    pub api_key: String,
    #[sensitive(Email)]
    pub user_email: String,
    #[not_sensitive]
    pub action: String,
}

/// Structural fixture: `Sensitive` derive with one annotated leaf.
#[derive(Clone, Sensitive, serde::Serialize)]
pub struct FixtureUser {
    #[not_sensitive]
    pub name: String,
    #[sensitive(Secret)]
    pub api_key: String,
}

/// Structural enum fixture: production `Debug` must use compact variant names.
#[derive(Clone, Sensitive, serde::Serialize)]
pub enum FixtureEvent {
    Login {
        #[not_sensitive]
        user: String,
        #[sensitive(Secret)]
        token: String,
    },
}

// Display fixture: `SensitiveDisplay` derive with one annotated leaf. The doc
// comment is the display template, so the explanation lives in this comment.
/// login failed for {user} with {password}
#[derive(SensitiveDisplay)]
pub struct FixtureError {
    #[not_sensitive]
    pub user: String,
    #[sensitive(Secret)]
    pub password: String,
}

/// Genuine generic dual derive compiled outside `cfg(test)`.
#[derive(Clone, SensitiveDual, serde::Serialize)]
#[error("{label}: {secret}")]
pub struct GenericDualFixture<T: Display> {
    #[not_sensitive]
    pub label: T,
    #[sensitive(Secret)]
    pub secret: String,
}

// =============================================================================
// E0446 regression guard
// =============================================================================
//
// A `pub` type deriving `Sensitive` must not leak the visibility of its field
// types. The removed owned-capability hierarchy did exactly that: the derive
// emitted `type Driver = __RedactableOwnedCapability<Self, #field_types..>` as a
// public associated type on a public trait impl, so any private field type
// appeared in a public interface and rustc rejected the whole type with
// `error[E0446]: private type `PrivateDetail` in public interface`.
//
// This crate is a library, so a public/private boundary is real here and E0446
// is enforced (a binary's effective visibility would mask it). `PrivateDetail`
// must stay private and `PublicRedactedEvent` must stay `pub` for this guard to
// mean anything. Deriving is the whole assertion: if the generated code ever
// leaks a field type into a public interface again, this crate fails to compile
// and every downstream target fails with it.

/// Deliberately private field type for the E0446 guard below.
#[derive(Clone, Debug, serde::Serialize)]
struct PrivateDetail {
    note: String,
}

impl RedactableWithMapper for PrivateDetail {
    fn redact_with<M: RedactableMapper>(self, _mapper: &M) -> Self {
        self
    }
}

impl Redactable for PrivateDetail {}

/// Public type whose field type is private: must compile (see E0446 note above).
#[derive(Clone, Sensitive, serde::Serialize)]
pub struct PublicRedactedEvent {
    #[sensitive(Secret)]
    pub token: String,
    detail: PrivateDetail,
}

impl PublicRedactedEvent {
    /// Builds the guard fixture; `note` is readable only through this crate.
    #[must_use]
    pub fn new(token: &str, note: &str) -> Self {
        Self {
            token: token.to_owned(),
            detail: PrivateDetail {
                note: note.to_owned(),
            },
        }
    }

    /// Returns the private field's contents so callers can assert passthrough.
    #[must_use]
    pub fn detail_note(&self) -> &str {
        &self.detail.note
    }
}
