use redactable::{Sensitive, ToRedacted};

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
    #[not_sensitive]
    value: std::cell::Cell<u8>,
}

#[derive(Clone, Sensitive, serde::Serialize)]
struct DirectStdRefCell {
    #[not_sensitive]
    value: std::cell::RefCell<String>,
}

fn assert_output<T: ToRedacted>(value: &T) {
    let _ = value.to_redacted();
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
        use redactable::__private::slog::Value;

        fn assert_slog<T: Value>() {}
        assert_slog::<Direct>();
        assert_slog::<Generic<String>>();
        assert_slog::<Generic<RefCell>>();
        assert_slog::<Generic<Option<String>>>();
        assert_slog::<Generic<Cell<String>>>();
        assert_slog::<DirectStdCell>();
        assert_slog::<DirectStdRefCell>();
    }
}
