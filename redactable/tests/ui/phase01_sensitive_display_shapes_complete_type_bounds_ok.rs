use serde::Serialize;
use std::{
    cell::Cell,
    fmt::{Display, Formatter, Result as FmtResult},
};

use redactable::{
    __private::DeclaredFormatting, NotSensitiveDisplay, RedactableWithFormatter, SensitiveDisplay,
};

#[derive(serde::Serialize, SensitiveDisplay)]
#[error("named {value}")]
struct Named<T: Copy + Serialize> where Cell<T>: DeclaredFormatting {
    value: Cell<T>,
}

#[derive(serde::Serialize, SensitiveDisplay)]
#[error("tuple {0}")]
struct Tuple<T: Copy + Serialize>(Cell<T>) where Cell<T>: DeclaredFormatting;

#[derive(serde::Serialize, SensitiveDisplay)]
enum Shapes<T: Copy + Serialize> where Cell<T>: DeclaredFormatting {
    #[error("enum named {value}")]
    Named { value: Cell<T> },
    #[error("enum tuple {0}")]
    Tuple(Cell<T>),
}

fn format_named<T>(value: &Named<T>) -> String
where
    T: Copy + Serialize,
    Cell<T>: DeclaredFormatting,
{
    value.redacted_display().to_string()
}

fn format_tuple<T>(value: &Tuple<T>) -> String
where
    T: Copy + Serialize,
    Cell<T>: DeclaredFormatting,
{
    value.redacted_display().to_string()
}

fn format_shape<T>(value: &Shapes<T>) -> String
where
    T: Copy + Serialize,
    Cell<T>: DeclaredFormatting,
{
    value.redacted_display().to_string()
}

#[derive(Clone, Copy, Debug, NotSensitiveDisplay, serde::Serialize)]
struct PublicCount(u8);
impl Display for PublicCount {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        self.0.fmt(f)
    }
}

fn main() {
    assert_eq!(
        format_named(&Named {
            value: Cell::new(PublicCount(1))
        }),
        "named 1"
    );
    assert_eq!(format_tuple(&Tuple(Cell::new(PublicCount(2)))), "tuple 2");
    assert_eq!(
        format_shape(&Shapes::Named {
            value: Cell::new(PublicCount(3)),
        }),
        "enum named 3"
    );
    assert_eq!(
        format_shape(&Shapes::Tuple(Cell::new(PublicCount(4)))),
        "enum tuple 4"
    );
}
