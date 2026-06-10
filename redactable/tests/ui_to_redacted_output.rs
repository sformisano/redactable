mod to_redacted_output {
    // The expected stderr lists every ToRedactedOutput implementor, and that
    // list includes json-gated types, so the snapshot only matches when the
    // json feature is enabled (CI covers it via the all-features run).
    #[cfg(feature = "json")]
    #[test]
    fn rejects_raw_string() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/to_redacted_output_raw_string_rejected.rs");
    }

    #[test]
    fn accepts_certified_outputs() {
        let t = trybuild::TestCases::new();
        t.pass("tests/ui/to_redacted_output_certified_ok.rs");
    }
}
