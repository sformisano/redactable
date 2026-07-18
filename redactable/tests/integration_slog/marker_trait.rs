use super::*;

#[test]
fn sensitive_type_implements_slog_redacted() {
    #[derive(Clone, Sensitive, Serialize)]
    struct Account {
        #[sensitive(Email)]
        email: String,
    }

    fn assert_slog_redacted<T: SlogRedacted>() {}

    assert_slog_redacted::<Account>();
}
