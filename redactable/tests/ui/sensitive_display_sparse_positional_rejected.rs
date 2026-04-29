use redactable::SensitiveDisplay;

#[derive(SensitiveDisplay)]
enum SparseError {
    #[error("second field {1}")]
    Pair(String, String),
}

fn main() {}
