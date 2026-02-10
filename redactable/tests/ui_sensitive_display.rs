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
}
