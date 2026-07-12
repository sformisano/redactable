use redactable::{NotSensitiveDisplay, Secret, SensitiveValue, ToRedactedOutput};

fn require_output<T: ToRedactedOutput>(_: &T) {}

fn main() {
    let sensitive = SensitiveValue::<String, Secret>::from(String::from("secret"));
    require_output(&NotSensitiveDisplay(sensitive));
}
