#[test]
fn sensitive_display_requires_explicit_annotation() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/sensitive_display_missing_redactable_display.rs");
    t.pass("tests/ui/sensitive_display_raw_required.rs");
    t.pass("tests/ui/sensitive_display_raw_ok.rs");
    t.pass("tests/ui/sensitive_display_strict_ok.rs");
    t.pass("tests/ui/sensitive_display_nested_ok.rs");
}
