mod sensitive_display {
    #[test]
    fn accepts_raw_required_pattern() {
        let t = trybuild::TestCases::new();
        t.pass("tests/ui/sensitive_display_raw_required.rs");
    }

    #[test]
    fn accepts_raw_ok_pattern() {
        let t = trybuild::TestCases::new();
        t.pass("tests/ui/sensitive_display_raw_ok.rs");
    }

    #[test]
    fn accepts_strict_ok_pattern() {
        let t = trybuild::TestCases::new();
        t.pass("tests/ui/sensitive_display_strict_ok.rs");
    }

    #[test]
    fn accepts_nested_ok_pattern() {
        let t = trybuild::TestCases::new();
        t.pass("tests/ui/sensitive_display_nested_ok.rs");
    }

    #[test]
    fn accepts_policy_redacted_containers() {
        let t = trybuild::TestCases::new();
        t.pass("tests/ui/sensitive_display_policy_containers_ok.rs");
    }

    #[test]
    fn rejects_sparse_positional_placeholders() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/sensitive_display_sparse_positional_rejected.rs");
    }

    #[test]
    fn rejects_dynamic_width_or_precision() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/sensitive_display_dynamic_width_rejected.rs");
    }

    #[test]
    fn rejects_unsupported_format_specifier() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/sensitive_display_unsupported_specifier_rejected.rs");
    }

    #[test]
    fn rejects_variant_level_attribute() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/sensitive_display_variant_attr_rejected.rs");
    }
}
