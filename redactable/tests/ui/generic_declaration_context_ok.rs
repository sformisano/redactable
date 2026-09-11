use std::{collections::BTreeMap, marker::PhantomData};
use redactable::{Redactable, Secret, Sensitive, SensitiveDisplay, SensitiveValue};

trait Payload { type Value: Redactable; }
#[derive(Sensitive)]
struct Projection<T: Payload> { value: T::Value }
#[derive(Sensitive)]
struct Defaults<T: Redactable = SensitiveValue<String, Secret>> { value: T }
#[derive(SensitiveDisplay)]
#[error("{value}")]
struct Borrowed<'a, const N: usize> {
    #[not_sensitive]
    value: &'a str,
    marker: PhantomData<[u8; N]>,
}
#[derive(Sensitive)]
struct SelfBound<T> where Self: Payload, <Self as Payload>::Value: Redactable {
    value: <Self as Payload>::Value,
    marker: PhantomData<T>,
}
impl<T> Payload for SelfBound<T> { type Value = SensitiveValue<String, Secret>; }
#[derive(Sensitive)]
struct Exempt<K, V: Redactable> where BTreeMap<K,V>: Redactable {
    values: BTreeMap<K,V>,
    marker: PhantomData<K>,
    #[not_sensitive]
    public: K,
}
fn main() {
    assert_eq!(format!("{:?}", Borrowed::<3> { value: "public", marker: PhantomData }), "public");
}
