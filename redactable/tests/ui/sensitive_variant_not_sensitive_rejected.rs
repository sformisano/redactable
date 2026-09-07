use redactable::Sensitive;

#[derive(Clone, serde::Serialize, Sensitive)]
enum Event {
    #[not_sensitive]
    Message { value: String },
}

fn main() {}
