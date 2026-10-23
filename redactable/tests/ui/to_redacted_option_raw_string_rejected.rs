use redactable::ToRedacted;

fn assert_redacted_output<T: ToRedacted>(_: &T) {}

fn main() {
    assert_redacted_output(&Some(String::from("secret")));
    assert_redacted_output(&None::<String>);
}
