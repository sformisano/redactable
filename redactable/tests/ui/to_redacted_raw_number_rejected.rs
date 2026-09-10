use redactable::ToRedacted;

fn require_output<T: ToRedacted>(_: &T) {}

fn main() {
    require_output(&42_u64);
}
