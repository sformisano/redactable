use redactable::SensitiveDual;

#[derive(SensitiveDual)]
enum Event {
    #[error("{value}")]
    #[redactable(legacy_formatting)]
    Message { value: String },
}

fn main() {}
