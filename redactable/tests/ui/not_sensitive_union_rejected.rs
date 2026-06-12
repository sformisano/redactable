use redactable::NotSensitive;

#[derive(NotSensitive)]
union PublicUnion {
    value: u32,
}

fn main() {}
