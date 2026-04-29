use redactable::SensitiveDisplay;

#[derive(SensitiveDisplay)]
#[error("value {value:x}")]
struct UnsupportedSpecifier {
    value: u32,
}

fn main() {}
