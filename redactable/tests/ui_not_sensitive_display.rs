mod not_sensitive_display {
    #[test]
    fn with_template_compiles_without_not_sensitive() {
        let t = trybuild::TestCases::new();
        t.pass("tests/ui/not_sensitive_display_template_ok.rs");
    }

    #[test]
    fn inside_sensitive_container_compiles() {
        let t = trybuild::TestCases::new();
        t.pass("tests/ui/not_sensitive_display_in_container_ok.rs");
    }

    #[test]
    fn rejects_sensitive_attribute() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/not_sensitive_display_sensitive_rejected.rs");
    }

    #[test]
    fn no_template_behaves_unchanged() {
        let t = trybuild::TestCases::new();
        t.pass("tests/ui/not_sensitive_display_no_template_ok.rs");
    }
}
