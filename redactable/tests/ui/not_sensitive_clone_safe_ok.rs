use redactable::{NotSensitive, ToRedacted};

#[derive(Clone, Debug, NotSensitive, serde::Serialize)]
struct Generic<T>(T);

#[derive(Clone, Debug, serde::Serialize)]
struct RefCell(String);

fn output<T: ToRedacted>(value: &T) {
    let _ = value.to_redacted();
}

fn main() {
    output(&Generic(String::from("safe")));
    output(&Generic(RefCell(String::from("lookalike"))));

    #[cfg(feature = "slog")]
    {
        fn assert_slog<T: redactable::__private::slog::Value>() {}
        assert_slog::<Generic<String>>();
        assert_slog::<Generic<RefCell>>();
    }
}
