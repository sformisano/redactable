use redactable::SensitiveDisplay;

#[derive(Debug)]
struct PlainContext;

impl std::fmt::Display for PlainContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("plain")
    }
}

#[derive(SensitiveDisplay)]
enum LoginError {
    #[error("context {context}")]
    Invalid {
        #[not_sensitive]
        context: PlainContext,
    },
}

fn main() {}
