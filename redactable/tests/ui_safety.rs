use trybuild::TestCases;

#[test]
fn declared_fields_preserve_supported_composition() {
    let cases = TestCases::new();
    cases.pass("tests/ui/safety_declarations_ok.rs");
    cases.pass("tests/ui/safety_selected_templates_ok.rs");
    cases.pass("tests/ui/safety_manual_output_ok.rs");
}

#[test]
fn undeclared_fields_and_override_siblings_are_rejected() {
    let cases = TestCases::new();
    if cfg!(feature = "json") {
        cases.compile_fail("tests/ui/safety_undecided_fields_json.rs");
        cases.compile_fail("tests/ui/safety_undecided_sets_json.rs");
        cases.compile_fail("tests/ui/safety_recursive_overrides_json.rs");
        cases.compile_fail("tests/ui/safety_missing_companion_json.rs");
    } else {
        cases.compile_fail("tests/ui/safety_undecided_fields.rs");
        cases.compile_fail("tests/ui/safety_undecided_sets.rs");
        cases.compile_fail("tests/ui/safety_recursive_overrides.rs");
        cases.compile_fail("tests/ui/safety_missing_companion.rs");
    }
}

#[test]
fn output_options_have_targeted_scope_and_syntax_errors() {
    let cases = TestCases::new();
    cases.compile_fail("tests/ui/safety_output_options.rs");
    if cfg!(feature = "json") {
        cases.pass("tests/ui/safety_json_output_ok.rs");
        cases.compile_fail("tests/ui/safety_json_missing_bounds.rs");
    } else {
        cases.compile_fail("tests/ui/safety_json_feature_required.rs");
    }
}

#[test]
fn anonymous_output_construction_is_unavailable() {
    let cases = TestCases::new();
    cases.compile_fail("tests/ui/safety_output_text_construction.rs");
    cases.compile_fail("tests/ui/safety_output_view_mutation.rs");
    cases.compile_fail("tests/ui/safety_output_text_borrow_mutation.rs");
    if cfg!(feature = "json") {
        cases.compile_fail("tests/ui/safety_output_json_construction.rs");
        cases.compile_fail("tests/ui/safety_output_json_borrow_mutation.rs");
    }
}
