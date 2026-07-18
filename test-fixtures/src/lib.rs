//! Fixture types for asserting derive-generated `Debug` behavior outside
//! test builds.
//!
//! This crate is compiled as a dependency, so `cfg!(test)` is false inside it.
//! Derive-generated `Debug` impls on these types therefore take the production
//! (redacted) branch unless `redactable`'s `testing` feature is enabled, which
//! is exactly the behavior the integration tests in the `redactable` crate
//! assert. Keep these types out of the main crate: types defined inside unit
//! or integration tests always see `cfg!(test) == true` and can never exercise
//! the production branch.

use redactable::{
    Email, RedactableMapper, RedactableWithMapper, Secret, Sensitive, SensitiveDisplay,
    SensitiveDual, Token,
};

/// Exact README tracing fixture with production-compiled generated `Debug`.
#[derive(Clone, Sensitive, serde::Serialize)]
pub struct AuthEvent {
    #[sensitive(Token)]
    pub api_key: String,
    #[sensitive(Email)]
    pub user_email: String,
    pub action: String,
}

/// Structural fixture: `Sensitive` derive with one annotated leaf.
#[derive(Clone, Sensitive, serde::Serialize)]
pub struct FixtureUser {
    pub name: String,
    #[sensitive(Secret)]
    pub api_key: String,
}

/// Structural enum fixture: production `Debug` must use compact variant names.
#[derive(Clone, Sensitive, serde::Serialize)]
pub enum FixtureEvent {
    Login {
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
    pub user: String,
    #[sensitive(Secret)]
    pub password: String,
}

/// Genuine generic dual derive compiled outside `cfg(test)`.
#[derive(Clone, SensitiveDual, serde::Serialize)]
#[error("{label}: {secret}")]
pub struct GenericDualFixture<T> {
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
