use redactable::ToRedactedOutput;

fn assert_redacted_output<T: ToRedactedOutput>(_: &T) {}

fn main() {
    let raw = String::from("secret");
    assert_redacted_output(&raw);
}
