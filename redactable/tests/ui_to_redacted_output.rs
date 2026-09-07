mod to_redacted {
    use trybuild::TestCases;

    // The expected stderr lists every ToRedacted implementor, and that list
    // grows with optional features, so the snapshot only matches under the
    // all-features run that CI performs.
    #[cfg(feature = "json")]
    #[test]
    fn rejects_raw_and_undeclared_values() {
        let t = TestCases::new();
        t.compile_fail("tests/ui/to_redacted_raw_string_rejected.rs");
        t.compile_fail("tests/ui/to_redacted_arbitrary_display_rejected.rs");
        t.compile_fail("tests/ui/to_redacted_arbitrary_debug_rejected.rs");
        t.compile_fail("tests/ui/to_redacted_raw_number_rejected.rs");
        t.compile_fail("tests/ui/bypass_redaction_output_rejected.rs");
        t.compile_fail("tests/ui/not_sensitive_debug_requires_debug.rs");
        t.compile_fail("tests/ui/not_sensitive_display_requires_display.rs");
        t.compile_fail("tests/ui/not_sensitive_display_sensitive_value_requires_display.rs");
    }

    #[test]
    fn accepts_certified_values() {
        let t = TestCases::new();
        t.pass("tests/ui/to_redacted_certified_ok.rs");
    }

    #[test]
    fn producer_availability_matches_clone_and_serialize_bounds() {
        let t = TestCases::new();
        t.pass("tests/ui/to_redacted_borrow_sensitive_map_key_ok.rs");
    }

    #[test]
    fn accepts_ordinary_custom_map_keys() {
        let t = TestCases::new();
        t.pass("tests/ui/to_redacted_custom_map_key_ok.rs");
    }
}
