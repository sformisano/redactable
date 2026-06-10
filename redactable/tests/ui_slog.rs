#[cfg(feature = "slog")]
mod slog_certification {
    #[test]
    fn rejects_slog_redacted_display_on_raw_string() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/slog_redacted_display_raw_string_rejected.rs");
    }
}
