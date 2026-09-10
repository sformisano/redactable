use redactable::{BypassDisplayRedaction, Secret, SensitiveValue, ToRedacted};

fn require_output<T: ToRedacted>(_: &T) {}

fn main() {
    let sensitive = SensitiveValue::<String, Secret>::from(String::from("secret"));
    require_output(&BypassDisplayRedaction(sensitive));
}
