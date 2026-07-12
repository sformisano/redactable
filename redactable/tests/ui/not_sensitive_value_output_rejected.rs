use redactable::{NotSensitiveValue, ToRedactedOutput};

fn require_output<T: ToRedactedOutput>(_: &T) {}

fn main() {
    require_output(&NotSensitiveValue(String::from("ambiguous")));
}
