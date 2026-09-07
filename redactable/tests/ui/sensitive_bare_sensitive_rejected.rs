use redactable::Sensitive;

#[derive(serde::Serialize, Clone, Sensitive)]
struct Credentials {
    #[sensitive]
    password: String,
}

fn main() {}
