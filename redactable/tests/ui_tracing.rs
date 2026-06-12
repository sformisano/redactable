#[cfg(feature = "tracing")]
mod tracing_certification {
    #[test]
    fn rejects_tracing_redacted_debug_on_raw_string() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/tracing_redacted_debug_raw_string_rejected.rs");
    }
}
