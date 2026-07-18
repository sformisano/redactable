// Regression for review-round-6 Major: `TracingRedactedValue` must not be
// `Clone`. Cloning would hand out a second handle to shared interior-mutable
// inner state, letting a caller insert a fresh secret after redaction (through
// the clone) and have the original wrapper log it. The only way to reach the
// inner value must be the consuming `into_inner`, which leaves no original
// wrapper behind.
use redactable::tracing::IntoTracingRedactedValuableExt;
use redactable::{Secret, Sensitive};

#[derive(Sensitive, valuable::Valuable)]
struct Event {
    #[sensitive(Secret)]
    secret: u32,
}

fn main() {
    let wrapper = Event { secret: 42 }.into_tracing_redacted_valuable();
    let _second = wrapper.clone();
}
