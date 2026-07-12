use redactable::ToRedactedOutput;

fn require_output<T: ToRedactedOutput>(_: &T) {}

fn main() {
    require_output(&42_u64);
}
