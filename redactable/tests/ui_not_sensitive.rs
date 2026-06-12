mod not_sensitive {
    #[test]
    fn rejects_not_sensitive_attribute() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/not_sensitive_not_sensitive_rejected.rs");
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
}
