// The redacted inner value is available only through consuming extraction.
// Borrowing it would leave the certified wrapper alive while shared
// interior-mutable state could receive a fresh secret.
use redactable::tracing::IntoTracingRedactedValuableExt;
use redactable::{Secret, Sensitive};

#[derive(Sensitive, valuable::Valuable)]
struct Event {
    #[sensitive(Secret)]
    secret: u32,
}

fn main() {
    let wrapper = Event { secret: 42 }.into_tracing_redacted_valuable();
    let _borrowed = wrapper.inner();
}
