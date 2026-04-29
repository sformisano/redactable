mod to_redacted_output {
    #[test]
    fn rejects_raw_string() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/to_redacted_output_raw_string_rejected.rs");
    }

    #[test]
    fn accepts_certified_outputs() {
        let t = trybuild::TestCases::new();
        t.pass("tests/ui/to_redacted_output_certified_ok.rs");
    }
}
