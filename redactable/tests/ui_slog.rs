#[cfg(feature = "slog")]
mod slog_certification {
    use trybuild::TestCases;

    #[test]
    fn rejects_slog_redacted_on_raw_string() {
        let t = TestCases::new();
        t.compile_fail("tests/ui/slog_redacted_raw_string_rejected.rs");
    }

    #[test]
    fn accepts_a_producer_without_a_formatter() {
        let t = TestCases::new();
        t.pass("tests/ui/slog_redacted_sensitive_producer_ok.rs");
        t.pass("tests/ui/bypass_marker_slog_ok.rs");
    }
}
