use redactable::{RedactedOutputExt, Sensitive, ToRedactedOutput};

#[derive(Clone, Sensitive, serde::Serialize)]
struct Direct {
    #[not_sensitive]
    value: String,
}

#[derive(Clone, Sensitive, serde::Serialize)]
struct Generic<T> {
    #[not_sensitive]
    value: T,
}

#[derive(Clone, Debug, serde::Serialize)]
struct RefCell(String);

#[derive(Clone, Debug, serde::Serialize)]
struct Option<T>(T);

#[derive(Clone, Debug, serde::Serialize)]
struct Cell<T>(T);

#[derive(Clone, Sensitive, serde::Serialize)]
struct DirectStdCell {
    value: std::cell::Cell<u8>,
}

#[derive(Clone, Sensitive, serde::Serialize)]
struct DirectStdRefCell {
    #[not_sensitive]
    value: std::cell::RefCell<String>,
}

fn assert_output<T>(value: &T)
where
    T: redactable::Redactable + Clone + std::fmt::Debug + std::panic::RefUnwindSafe,
{
    let _ = value.redacted_output().to_redacted_output();
}

fn main() {
    assert_output(&Direct {
        value: "safe".into(),
    });
    assert_output(&Generic {
        value: String::from("safe"),
    });
    assert_output(&Generic {
        value: RefCell("lookalike".into()),
    });
    assert_output(&Generic {
        value: Option(String::from("lookalike")),
    });
    assert_output(&Generic {
        value: Cell(String::from("lookalike")),
    });

    #[cfg(feature = "slog")]
    {
        fn assert_slog<T: redactable::__private::slog::Value>() {}
        assert_slog::<Direct>();
        assert_slog::<Generic<String>>();
        assert_slog::<Generic<RefCell>>();
        assert_slog::<Generic<Option<String>>>();
        assert_slog::<Generic<Cell<String>>>();
        assert_slog::<DirectStdCell>();
        assert_slog::<DirectStdRefCell>();
    }
}
