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

use redactable::{Secret, Sensitive, SensitiveDisplay};

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
