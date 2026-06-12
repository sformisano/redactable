use redactable::Sensitive;

#[derive(Clone, Sensitive)]
struct Credentials {
    #[sensitive]
    password: String,
}

fn main() {}
