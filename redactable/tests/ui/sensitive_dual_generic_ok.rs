use std::marker::PhantomData;

use redactable::SensitiveDual;

#[derive(Clone, serde::Serialize, SensitiveDual)]
#[error("{value}")]
struct Dual<T> {
    #[sensitive(redactable::Secret)]
    value: String,
    #[not_sensitive]
    marker: PhantomData<T>,
}

fn main() {
    const CANARY: &str = "dual-generic-secret-canary";
    let value = Dual::<u8> {
        value: CANARY.into(),
        marker: PhantomData,
    };
    let rendered = format!("{value:?}");
    if !redactable::__TESTING {
        assert!(!rendered.contains(CANARY));
    }
}
