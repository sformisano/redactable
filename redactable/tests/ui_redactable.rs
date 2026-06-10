mod redactable_certification {
    #[test]
    fn rejects_raw_string() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/redactable_raw_string_rejected.rs");
    }
}
