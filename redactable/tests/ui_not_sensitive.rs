mod not_sensitive {
    #[test]
    fn rejects_not_sensitive_attribute() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/not_sensitive_not_sensitive_rejected.rs");
    }

    #[test]
    fn rejects_sensitive_attribute_once() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/not_sensitive_sensitive_rejected.rs");
    }

    #[test]
    fn rejects_union() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/not_sensitive_union_rejected.rs");
    }

    #[test]
    fn rejects_variant_level_attribute() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/not_sensitive_variant_attr_rejected.rs");
    }

    #[test]
    fn clone_logging_keeps_refcell_api_available() {
        let t = trybuild::TestCases::new();
        t.pass("tests/ui/not_sensitive_clone_safe_ok.rs");
        t.pass("tests/ui/not_sensitive_refcell_clone_rejected.rs");
    }
}
