//! `NotSensitive` and `NotSensitiveDisplay` still resolve — to the derive
//! macros of the same names — so the removal is reported at the use site.

use redactable::{NotSensitive, NotSensitiveDisplay};

fn type_position(_: NotSensitiveDisplay<u64>, _: NotSensitive<u64>) {}

fn main() {
    let _ = NotSensitiveDisplay(42_u64);
    let _ = NotSensitive(42_u64);
}
