use redactable::{PolicyDebug, PolicyDisplay, Secret, SensitiveDisplay, SensitiveDual};
use redactable::__private::PolicyField;

#[derive(SensitiveDisplay)]
#[error("{value}")]
struct DisplayOnly<T: PolicyDisplay<Secret>> { #[sensitive(Secret)] value: T }
#[derive(SensitiveDisplay)]
#[error("{value:?}")]
struct DebugOnly<T: PolicyDebug<Secret>> { #[sensitive(Secret)] value: T }
#[derive(SensitiveDisplay)]
#[error("{value} {value:?}")]
struct Both<T: PolicyDisplay<Secret> + PolicyDebug<Secret>> { #[sensitive(Secret)] value: T }
#[derive(SensitiveDual)]
#[error("{value}")]
struct Dual<T: PolicyField<Secret> + PolicyDisplay<Secret>> { #[sensitive(Secret)] value: T }
fn main() {
    assert_eq!(format!("{:?}", DisplayOnly { value: 42_u32 }), "0");
    assert_eq!(format!("{:?}", DebugOnly { value: 42_u32 }), "0");
    assert_eq!(format!("{:?}", Both { value: 42_u32 }), "0 0");
    assert_eq!(format!("{:?}", Dual { value: 42_u32 }), "0");
}
