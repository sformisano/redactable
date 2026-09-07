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
fn the_removed_output_attribute_reports_its_migration() {
    let cases = TestCases::new();
    cases.compile_fail("tests/ui/safety_output_options.rs");
    cases.compile_fail("tests/ui/safety_removed_output_attribute.rs");
}

#[test]
fn mandatory_bounds_are_reported_on_the_derive() {
    let cases = TestCases::new();
    cases.pass("tests/ui/safety_mandatory_bounds_ok.rs");
    cases.compile_fail("tests/ui/safety_mandatory_bounds.rs");
}

#[test]
fn anonymous_value_construction_is_unavailable() {
    let cases = TestCases::new();
    cases.compile_fail("tests/ui/safety_value_construction.rs");
    cases.compile_fail("tests/ui/safety_value_no_view.rs");
    cases.pass("tests/ui/safety_value_fallbacks_ok.rs");
}

#[test]
fn the_hidden_derive_channel_refuses_payloads() {
    let cases = TestCases::new();
    cases.compile_fail("tests/ui/safety_hidden_channel_construction.rs");
    cases.pass("tests/ui/safety_hidden_channel_ok.rs");
}

#[test]
fn the_bypass_family_is_constructed_by_tuple_syntax() {
    let cases = TestCases::new();
    cases.pass("tests/ui/safety_bypass_family_ok.rs");
    cases.compile_fail("tests/ui/bypass_removed_names_unresolved.rs");
    cases.compile_fail("tests/ui/bypass_shadowed_names.rs");
}
