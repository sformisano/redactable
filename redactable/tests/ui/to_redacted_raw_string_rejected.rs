use redactable::ToRedacted;

fn assert_redacted_output<T: ToRedacted>(_: &T) {}

fn main() {
    let raw = String::from("secret");
    assert_redacted_output(&raw);
}
