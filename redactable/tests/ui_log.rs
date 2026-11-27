#![cfg(any(feature = "log", feature = "slog", feature = "tracing"))]

#[test]
fn checked_log_rejects_undeclared_fields_and_message_data() {
    let tests = trybuild::TestCases::new();
    // Each compiled emitter produces its own type-bound diagnostic. Run the
    // shared snapshot for each backend in isolation to check every emitter.
    let backends = [
        cfg!(feature = "log"),
        cfg!(feature = "slog"),
        cfg!(feature = "tracing"),
    ];
    if backends.into_iter().filter(|enabled| *enabled).count() == 1 {
        tests.compile_fail("tests/ui/log_unchecked_fields_rejected.rs");
    }
    tests.compile_fail("tests/ui/log_unchecked_messages_rejected.rs");
    tests.compile_fail("tests/ui/log_unchecked_field_syntax_rejected.rs");
    tests.compile_fail("tests/ui/log_duplicate_fields_rejected.rs");
}
