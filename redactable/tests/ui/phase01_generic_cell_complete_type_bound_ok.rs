use std::cell::Cell;

use redactable::{Redactable, RedactableWithMapper, Sensitive};

#[derive(Clone, serde::Serialize, Sensitive)]
struct GenericCell<T: Copy + serde::Serialize> {
    value: Cell<T>,
}

fn redact_cell<T>(value: GenericCell<T>) -> GenericCell<T>
where
    T: Copy + serde::Serialize,
    Cell<T>: RedactableWithMapper,
{
    value.redact()
}

fn main() {
    let value = redact_cell(GenericCell {
        value: Cell::new(7_u8),
    });
    assert_eq!(value.value.get(), 7);
}
