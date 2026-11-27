use std::fmt;

use safe::{NotSensitive, NotSensitiveDisplay, Secret, Sensitive, SensitiveDisplay, SensitiveDual};
use serde::Serialize;

#[derive(Clone, Sensitive, Serialize)]
struct Structured(#[sensitive(Secret)] String);

#[derive(SensitiveDisplay)]
#[error("token {0}")]
struct Text(#[sensitive(Secret)] String);

#[derive(Clone, SensitiveDual, Serialize)]
#[error("token {0}")]
struct Dual(#[sensitive(Secret)] String);

#[derive(NotSensitive, Serialize)]
struct Public(u64);

#[derive(NotSensitiveDisplay)]
struct PublicText;

impl fmt::Display for PublicText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ready")
    }
}

// The build script and application compile these declarations with different runtime backends.
pub fn require_backend_impls() {
    fn require<T: crate::BackendMarker>() {}
    require::<Structured>();
    require::<Text>();
    require::<Dual>();
    require::<Public>();
    require::<PublicText>();
}
