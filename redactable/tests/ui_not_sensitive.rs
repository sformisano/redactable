mod not_sensitive {
    #[test]
    fn rejects_not_sensitive_attribute() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/not_sensitive_not_sensitive_rejected.rs");
    }
}
