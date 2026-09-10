use redactable::SensitiveDual;

#[derive(Clone, serde::Serialize, SensitiveDual)]
enum Event {
    #[error("{value}")]
    #[redactable(legacy_formatting)]
    Message { value: String },
}

fn main() {}
