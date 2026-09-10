mod redactable_certification {
    use trybuild::TestCases;

    #[test]
    fn rejects_uncertified_redactable_trait_use() {
        let t = TestCases::new();
        t.compile_fail("tests/ui/redactable_raw_string_rejected.rs");
    }

    #[test]
    fn accepts_certified_free_redaction_and_explicit_raw_policy() {
        let t = TestCases::new();
        t.pass("tests/ui/redact_free_certified_ok.rs");
        t.pass("tests/ui/redact_free_raw_traversal_ok.rs");
    }
}
