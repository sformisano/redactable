use redactable::{NotSensitive, RedactedOutputExt, ToRedactedOutput};

#[derive(Clone, Debug, NotSensitive, serde::Serialize)]
struct Generic<T>(T);

#[derive(Clone, Debug, serde::Serialize)]
struct RefCell(String);

fn output<T>(value: &T)
where
    T: redactable::Redactable + Clone + std::fmt::Debug + std::panic::RefUnwindSafe,
{
    let _ = value.redacted_output().to_redacted_output();
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
