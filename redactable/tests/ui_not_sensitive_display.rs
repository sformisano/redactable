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
    fn rejects_union() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/not_sensitive_display_union_rejected.rs");
    }

    #[test]
    fn no_template_behaves_unchanged() {
        let t = trybuild::TestCases::new();
        t.pass("tests/ui/not_sensitive_display_no_template_ok.rs");
    }

    #[test]
    fn foreign_type_compiles() {
        let t = trybuild::TestCases::new();
        t.pass("tests/ui/not_sensitive_display_foreign_type_ok.rs");
    }

    #[test]
    fn rejects_not_sensitive_attribute() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/not_sensitive_display_not_sensitive_rejected.rs");
    }

    #[test]
    fn direct_display_and_clone_json_keep_refcell_api_available() {
        let t = trybuild::TestCases::new();
        t.pass("tests/ui/not_sensitive_display_clone_safe_ok.rs");
        if cfg!(feature = "json") {
            t.pass("tests/ui/not_sensitive_display_refcell_clone_rejected.rs");
        }
    }
}
