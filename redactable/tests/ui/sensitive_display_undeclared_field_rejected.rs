use redactable::SensitiveDisplay;

#[derive(SensitiveDisplay)]
enum LoginError {
    #[error("context {context}")]
    Invalid { context: String },
}

fn main() {}
