mod to_redacted_output {
    // The expected stderr lists every ToRedactedOutput implementor, and that
    // list includes json-gated types, so the snapshot only matches when the
    // json feature is enabled (CI covers it via the all-features run).
    #[cfg(feature = "json")]
    #[test]
    fn rejects_raw_string() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/to_redacted_output_raw_string_rejected.rs");
        t.compile_fail("tests/ui/to_redacted_output_arbitrary_display_rejected.rs");
        t.compile_fail("tests/ui/to_redacted_output_arbitrary_debug_rejected.rs");
        t.compile_fail("tests/ui/to_redacted_output_raw_number_rejected.rs");
        t.compile_fail("tests/ui/not_sensitive_value_output_rejected.rs");
        t.compile_fail("tests/ui/not_sensitive_debug_requires_debug.rs");
        t.compile_fail("tests/ui/not_sensitive_display_requires_display.rs");
        t.compile_fail("tests/ui/not_sensitive_display_sensitive_value_rejected.rs");
    }

    #[test]
    fn accepts_certified_outputs() {
        let t = trybuild::TestCases::new();
        t.pass("tests/ui/to_redacted_output_certified_ok.rs");
    }

    #[test]
    fn redacted_output_availability_matches_clone_and_debug_bounds() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/redacted_output_raw_string_rejected.rs");
        t.pass("tests/ui/redacted_output_borrow_sensitive_map_key_rejected.rs");
    }

    #[test]
    fn accepts_ordinary_custom_map_keys() {
        let t = trybuild::TestCases::new();
        t.pass("tests/ui/redacted_output_custom_map_key_ok.rs");
    }

    #[cfg(not(feature = "json"))]
    #[test]
    fn serde_support_requires_json_feature() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/not_sensitive_output_serde_requires_json.rs");
    }
}
