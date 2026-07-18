#[cfg(feature = "tracing")]
mod tracing_certification {
    #[test]
    fn rejects_tracing_redacted_debug_on_raw_string() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/tracing_redacted_debug_raw_string_rejected.rs");
    }
}

#[cfg(feature = "tracing-valuable")]
mod tracing_valuable_wrapper {
    #[test]
    fn rejects_cloning_the_redacted_value_wrapper() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/tracing_redacted_value_not_clone.rs");
    }

    #[test]
    fn rejects_borrowing_the_redacted_value_wrapper_inner() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/tracing_redacted_value_no_borrowed_inner.rs");
    }
}
