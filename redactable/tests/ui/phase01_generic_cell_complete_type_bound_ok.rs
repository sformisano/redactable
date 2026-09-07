use serde::Serialize;
use std::cell::Cell;

use redactable::{NotSensitive, Redactable, Sensitive};

#[derive(Clone, serde::Serialize, Sensitive)]
struct GenericCell<T: Copy + Serialize> {
    value: Cell<T>,
}

fn redact_cell<T>(value: GenericCell<T>) -> GenericCell<T>
where
    T: Copy + Serialize,
    Cell<T>: Redactable,
{
    value.redact()
}

#[derive(Clone, Copy, Debug, NotSensitive, serde::Serialize)]
struct PublicCount(u8);

fn main() {
    let value = redact_cell(GenericCell {
        value: Cell::new(PublicCount(7)),
    });
    assert_eq!(value.value.get().0, 7);
}
