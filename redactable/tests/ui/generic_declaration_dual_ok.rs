use redactable::{SensitiveDual, Redactable, __private::DeclaredFormatting};
#[derive(SensitiveDual)]
#[error("{value}")]
struct Envelope<T: DeclaredFormatting + Redactable> { value: T }

fn main() {}
