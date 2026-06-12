use redactable::Sensitive;

#[derive(Sensitive)]
union SecretUnion {
    value: u32,
}

fn main() {}
