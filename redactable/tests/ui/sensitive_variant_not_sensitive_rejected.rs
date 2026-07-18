use redactable::Sensitive;

#[derive(Sensitive)]
enum Event {
    #[not_sensitive]
    Message { value: String },
}

fn main() {}
