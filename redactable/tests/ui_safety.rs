#[path = "support/rustc_json.rs"]
mod rustc_json;

use std::{fs, process::Command};

use rustc_json::compiler_error_lines;
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
    if cfg!(feature = "slog") {
        cases.compile_fail("tests/ui/safety_undecided_fields_slog.rs");
        cases.compile_fail("tests/ui/safety_undecided_sets_slog.rs");
        cases.compile_fail("tests/ui/safety_recursive_overrides_slog.rs");
        cases.compile_fail("tests/ui/safety_missing_companion_slog.rs");
    } else {
        cases.compile_fail("tests/ui/safety_undecided_fields.rs");
        cases.compile_fail("tests/ui/safety_undecided_sets.rs");
        cases.compile_fail("tests/ui/safety_recursive_overrides.rs");
        cases.compile_fail("tests/ui/safety_missing_companion.rs");
    }
}

/// Cargo's rendered output merges identical diagnostics, so a stderr snapshot
/// cannot show an error emitted twice. The JSON stream keeps every emission.
#[test]
fn undeclared_fields_report_each_error_once() {
    const SOURCE: &str = r#"
use redactable::{DeclaredFormatting, Redactable, Secret, Sensitive, SensitiveDisplay, SensitiveDual};

#[derive(Clone, serde::Serialize)]
struct Opaque;

#[derive(Clone, serde::Serialize, Sensitive)]
struct StructuralOwner {
    structural_field: String,
}

#[derive(Clone, serde::Serialize, Sensitive)]
enum VariantOwner {
    TupleVariant(String),
    Named { named_variant_field: Vec<String> },
}

#[derive(Clone, serde::Serialize, Sensitive)]
struct PolicyOwner {
    #[sensitive(Secret)]
    policy_field: Opaque,
}

#[derive(SensitiveDisplay)]
#[error("{display_field}")]
struct DisplayOwner {
    display_field: String,
}

#[derive(Clone, serde::Serialize, SensitiveDual)]
#[error("summary")]
struct DualOwner {
    dual_field: String,
}

#[derive(Clone, serde::Serialize, Sensitive)]
struct GenericOwner<T: Redactable> {
    value: T,
    generic_struct_raw: String,
}

#[derive(SensitiveDisplay)]
#[error("{value} {public} {generic_template_raw}")]
struct GenericDisplayOwner<T: DeclaredFormatting> {
    value: T,
    #[not_sensitive]
    public: u32,
    generic_template_raw: String,
}

fn main() {}
"#;
    // Each name belongs to one owner, so an error that contains it reports that owner.
    const UNDECLARED: [&str; 8] = [
        "structural_field",
        "TupleVariant",
        "named_variant_field",
        "policy_field",
        "display_field",
        "dual_field",
        "generic_struct_raw",
        "generic_template_raw",
    ];

    let owner = tempfile::Builder::new()
        .prefix("rd-declaration-")
        .tempdir()
        .expect("owned fixture directory");
    let directory = owner.path();
    fs::create_dir(directory.join("src")).unwrap();
    let features = [
        ("slog", cfg!(feature = "slog")),
        ("tracing", cfg!(feature = "tracing")),
        ("tracing-valuable", cfg!(feature = "tracing-valuable")),
    ]
    .into_iter()
    .filter(|(_, enabled)| *enabled)
    .map(|(name, _)| format!("'{name}'"))
    .collect::<Vec<_>>()
    .join(",");
    fs::write(
        directory.join("Cargo.toml"),
        format!(
            "[package]\nname='declaration-diagnostics'\nversion='0.0.0'\nedition='2024'\npublish=false\n[workspace]\n[dependencies]\nserde={{version='1',features=['derive']}}\nredactable={{path='{}',features=[{features}]}}\n",
            env!("CARGO_MANIFEST_DIR")
        ),
    )
    .unwrap();
    fs::write(directory.join("src/main.rs"), SOURCE).unwrap();

    let output = Command::new(env!("CARGO"))
        .args([
            "check",
            "--offline",
            "--message-format",
            "json",
            "--manifest-path",
        ])
        .arg(directory.join("Cargo.toml"))
        .env("CARGO_TARGET_DIR", directory.join("target"))
        .output()
        .expect("fixture cargo check runs");
    assert!(!output.status.success(), "undeclared fields compiled");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let errors: Vec<&str> = stdout
        .lines()
        .filter(|message| compiler_error_lines(message).is_some())
        .collect();
    for field in UNDECLARED {
        let reports = errors.iter().filter(|error| error.contains(field)).count();
        assert_eq!(
            reports,
            1,
            "`{field}` has {reports} error-level diagnostics:\n{}",
            errors.join("\n")
        );
    }
    assert_eq!(
        errors.len(),
        UNDECLARED.len(),
        "unexpected error-level diagnostics:\n{}",
        errors.join("\n")
    );
}

#[test]
fn container_level_redactable_options_are_rejected() {
    let cases = TestCases::new();
    cases.compile_fail("tests/ui/safety_container_redactable_rejected.rs");
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
