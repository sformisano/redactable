use redactable::SensitiveDisplay;

#[derive(SensitiveDisplay)]
#[error("{value}")]
union DisplayUnion {
    value: u32,
}

fn main() {}
