mod sensitive {
    #[test]
    fn rejects_nonzero_policy_annotation() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/sensitive_nonzero_secret_rejected.rs");
    }

    #[test]
    fn rejects_variant_level_attribute() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/sensitive_variant_attr_rejected.rs");
    }
}
