use redactable::NotSensitiveDisplay;

#[derive(NotSensitiveDisplay)]
union PublicDisplayUnion {
    value: u32,
}

fn main() {}
