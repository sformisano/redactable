use std::cell::Cell;

use redactable::{RedactableWithFormatter, SensitiveDisplay};

#[derive(serde::Serialize, SensitiveDisplay)]
#[error("named {value}")]
struct Named<T: Copy + serde::Serialize> {
    value: Cell<T>,
}

#[derive(serde::Serialize, SensitiveDisplay)]
#[error("tuple {0}")]
struct Tuple<T: Copy + serde::Serialize>(Cell<T>);

#[derive(serde::Serialize, SensitiveDisplay)]
enum Shapes<T: Copy + serde::Serialize> {
    #[error("enum named {value}")]
    Named { value: Cell<T> },
    #[error("enum tuple {0}")]
    Tuple(Cell<T>),
}

fn format_named<T>(value: &Named<T>) -> String
where
    T: Copy + serde::Serialize,
    Cell<T>: RedactableWithFormatter,
{
    value.redacted_display().to_string()
}

fn format_tuple<T>(value: &Tuple<T>) -> String
where
    T: Copy + serde::Serialize,
    Cell<T>: RedactableWithFormatter,
{
    value.redacted_display().to_string()
}

fn format_shape<T>(value: &Shapes<T>) -> String
where
    T: Copy + serde::Serialize,
    Cell<T>: RedactableWithFormatter,
{
    value.redacted_display().to_string()
}

fn main() {
    assert_eq!(format_named(&Named { value: Cell::new(1_u8) }), "named 1");
    assert_eq!(format_tuple(&Tuple(Cell::new(2_u8))), "tuple 2");
    assert_eq!(
        format_shape(&Shapes::Named {
            value: Cell::new(3_u8),
        }),
        "enum named 3"
    );
    assert_eq!(
        format_shape(&Shapes::Tuple(Cell::new(4_u8))),
        "enum tuple 4"
    );
}
