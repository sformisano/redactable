use redactable::{SensitiveDual, __private::DeclaredFormatting};
#[derive(SensitiveDual)]
#[error("{value}")]
struct Envelope<T: DeclaredFormatting> { value: T }

fn main() {}
