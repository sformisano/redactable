use redactable::{SensitiveDisplay, PolicyDisplay, Email};
#[derive(SensitiveDisplay)]
#[error("{value}")]
struct Envelope<T: PolicyDisplay<Email>> { #[sensitive(Email)] value: T }
type Unsupported = Envelope<u32>;
fn require_type(_: Option<Unsupported>) {}

fn main() {}
