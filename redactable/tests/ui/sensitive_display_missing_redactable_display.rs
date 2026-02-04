use redactable::SensitiveDisplay;

struct ExternalContext;

impl std::fmt::Display for ExternalContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("external")
    }
}

#[derive(SensitiveDisplay)]
enum LoginError {
    #[error("context {context}")]
    Invalid { context: ExternalContext },
}

fn main() {}
