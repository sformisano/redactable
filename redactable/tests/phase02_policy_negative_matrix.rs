//! Generated downstream compile matrix for direct-only built-in policy leaves.

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[path = "support/rustc_json.rs"]
mod rustc_json;

use rustc_json::compiler_error_lines;

const EXPECTED_NEGATIVE_CELLS: usize = 696;
const EXPECTED_GRID_FINGERPRINT: u64 = 0xf7e9_12b5_ee1b_8b73;
const EXPECTED_POSITIVE_CONTROLS: usize = 12;
const EXPECTED_POSITIVE_FINGERPRINT: u64 = 0xd9ff_a05e_791a_2fc1;
const EXPECTED_POSITIVE_SOURCE_FINGERPRINT: u64 = 0x1776_2a6c_ac0d_1003;

const REQUIRED_POSITIVE_CONTROLS: &[(&str, &str, &str)] = &[
    (
        "HashMapCustomQualifiedSensitive",
        "struct CustomMap {",
        "let custom = CustomMap {",
    ),
    (
        "HashMapCustomShortSensitive",
        "struct CustomMapShort {",
        "let custom_short = CustomMapShort {",
    ),
    (
        "HashMapCustomQualifiedDisplay",
        "struct CustomMapDisplay {",
        "let rendered = CustomMapDisplay {",
    ),
    (
        "HashMapCustomShortDisplay",
        "struct CustomMapShortDisplay {",
        "let rendered = CustomMapShortDisplay {",
    ),
    (
        "HashMapGenericSensitive",
        "struct GenericMap<P:",
        "let generic = GenericMap::<safe::IpAddress>",
    ),
    (
        "HashMapGenericDisplay",
        "struct GenericMapDisplay<P:",
        "let display = GenericMapDisplay::<safe::IpAddress>",
    ),
    (
        "BTreeMapCustomQualifiedSensitive",
        "struct CustomBTreeMap {",
        "let custom_btree = CustomBTreeMap {",
    ),
    (
        "BTreeMapCustomShortSensitive",
        "struct CustomBTreeMapShort {",
        "let custom_btree_short = CustomBTreeMapShort {",
    ),
    (
        "BTreeMapCustomQualifiedDisplay",
        "struct CustomBTreeMapDisplay {",
        "let rendered = CustomBTreeMapDisplay {",
    ),
    (
        "BTreeMapCustomShortDisplay",
        "struct CustomBTreeMapShortDisplay {",
        "let rendered = CustomBTreeMapShortDisplay {",
    ),
    (
        "BTreeMapGenericSensitive",
        "struct GenericBTreeMap<P:",
        "let generic_btree = GenericBTreeMap::<safe::IpAddress>",
    ),
    (
        "BTreeMapGenericDisplay",
        "struct GenericBTreeMapDisplay<P:",
        "let generic_btree_display = GenericBTreeMapDisplay::<safe::IpAddress>",
    ),
];

const POLICY_FORMS: &[(&str, &str)] = &[
    ("Short", ""),
    ("Renamed", "safe::"),
    ("Absolute", "::safe::"),
];

const DETECTOR_COMPLEMENTS: &[(&str, &str)] = &[
    ("Reference", "&'static std::net::IpAddr"),
    ("Slice", "&'static [std::net::IpAddr]"),
    ("Tuple", "(std::net::IpAddr,)"),
    ("NestedGeneric", "Option<Vec<std::net::IpAddr>>"),
    ("FunctionInput", "fn(std::net::IpAddr)"),
    ("FunctionOutput", "fn() -> std::net::IpAddr"),
    ("Parenthesized", "(std::net::IpAddr)"),
];

#[derive(Debug)]
struct MatrixCell {
    id: String,
    semantic_descriptor: String,
    derive_line: usize,
}

const SCALARS: &[(&str, &str)] = &[
    ("I8", "i8"),
    ("I16", "i16"),
    ("I32", "i32"),
    ("I64", "i64"),
    ("I128", "i128"),
    ("Isize", "isize"),
    ("U8", "u8"),
    ("U16", "u16"),
    ("U32", "u32"),
    ("U64", "u64"),
    ("U128", "u128"),
    ("Usize", "usize"),
    ("F32", "f32"),
    ("F64", "f64"),
    ("Bool", "bool"),
    ("Char", "char"),
];

const IPS: &[(&str, &str)] = &[
    ("Ipv4", "std::net::Ipv4Addr"),
    ("Ipv6", "std::net::Ipv6Addr"),
    ("Ip", "std::net::IpAddr"),
    ("Socket", "std::net::SocketAddr"),
];

fn recursive_families(leaf: &str, ip: bool) -> Vec<(&'static str, String)> {
    let mut families = vec![
        ("Option", format!("Option<{leaf}>")),
        ("Vec", format!("Vec<{leaf}>")),
        ("VecDeque", format!("std::collections::VecDeque<{leaf}>")),
        ("Array", format!("[{leaf}; 1]")),
        ("Box", format!("Box<{leaf}>")),
        ("Arc", format!("std::sync::Arc<{leaf}>")),
        ("Rc", format!("std::rc::Rc<{leaf}>")),
        ("RefCell", format!("std::cell::RefCell<{leaf}>")),
        ("Cell", format!("std::cell::Cell<{leaf}>")),
        ("ResultOk", format!("Result<{leaf}, String>")),
        ("ResultErr", format!("Result<String, {leaf}>")),
        (
            "HashMapValue",
            format!("std::collections::HashMap<String, {leaf}>"),
        ),
        (
            "BTreeMapValue",
            format!("std::collections::BTreeMap<String, {leaf}>"),
        ),
        ("HashSet", format!("std::collections::HashSet<{leaf}>")),
        ("BTreeSet", format!("std::collections::BTreeSet<{leaf}>")),
    ];
    if ip {
        families.extend([
            (
                "HashMapKey",
                format!("std::collections::HashMap<{leaf}, String>"),
            ),
            (
                "BTreeMapKey",
                format!("std::collections::BTreeMap<{leaf}, String>"),
            ),
        ]);
    }
    families
}

fn policy_path(policy: &str, index: usize) -> String {
    match index % 3 {
        0 => policy.to_owned(),
        1 => format!("safe::{policy}"),
        _ => format!("::safe::{policy}"),
    }
}

fn push_reject(
    source: &mut String,
    cells: &mut Vec<MatrixCell>,
    name: &str,
    field_type: &str,
    policy: &str,
    display: bool,
) {
    let line = source.lines().count() + 1;
    cells.push(MatrixCell {
        id: name.to_owned(),
        semantic_descriptor: format!(
            "id={name}|field={field_type}|policy={policy}|derive={}",
            if display {
                "SensitiveDisplay"
            } else {
                "Sensitive"
            }
        ),
        derive_line: line,
    });
    if display {
        source.push_str(&format!(
            "#[derive(SensitiveDisplay)]\n#[error(\"{{value:?}}\")]\nstruct {name} {{ #[sensitive({policy})] value: {field_type} }}\n"
        ));
    } else {
        source.push_str(&format!(
            "#[derive(Clone, Sensitive)]\nstruct {name} {{ #[sensitive({policy})] value: {field_type} }}\n"
        ));
    }
}

fn negative_source() -> (String, Vec<MatrixCell>) {
    let mut source = r#"use safe::{Secret, IpAddress, Sensitive, SensitiveDisplay};
macro_rules! grouped_sensitive {
    ($name:ident, $ty:ty, $policy:path) => { #[derive(Clone, Sensitive)] struct $name { #[sensitive($policy)] value: $ty } };
}
macro_rules! grouped_display {
    ($name:ident, $ty:ty, $policy:path) => { #[derive(SensitiveDisplay)] #[error("{value:?}")] struct $name { #[sensitive($policy)] value: $ty } };
}
"#
    .to_owned();
    let mut cells = Vec::new();
    let mut index = 0;

    for &(identity, scalar) in SCALARS {
        source.push_str(&format!("type NegativeAlias{identity} = {scalar};\n"));
        for (family, field_type) in recursive_families(scalar, false) {
            for &(derive, display) in &[("Sensitive", false), ("Display", true)] {
                push_reject(
                    &mut source,
                    &mut cells,
                    &format!("Secret{identity}{family}{derive}"),
                    &field_type,
                    &policy_path("Secret", index),
                    display,
                );
                index += 1;
            }
        }
        for &(derive, display) in &[("Sensitive", false), ("Display", true)] {
            push_reject(
                &mut source,
                &mut cells,
                &format!("Secret{identity}RecursiveAlias{derive}"),
                &format!("Option<NegativeAlias{identity}>"),
                &policy_path("Secret", index),
                display,
            );
            index += 1;
        }
    }

    for &(identity, ip) in IPS {
        for (family, field_type) in recursive_families(ip, true) {
            for &(derive, display) in &[("Sensitive", false), ("Display", true)] {
                push_reject(
                    &mut source,
                    &mut cells,
                    &format!("Ip{identity}{family}{derive}"),
                    &field_type,
                    &policy_path("IpAddress", index),
                    display,
                );
                index += 1;
            }
        }
    }

    // Detector complements that are not distinct recursive runtime families.
    for &(name, field_type) in DETECTOR_COMPLEMENTS {
        for &(path_name, prefix) in POLICY_FORMS {
            for &(derive, display) in &[("Sensitive", false), ("Display", true)] {
                push_reject(
                    &mut source,
                    &mut cells,
                    &format!("Detector{name}{path_name}{derive}"),
                    field_type,
                    &format!("{prefix}IpAddress"),
                    display,
                );
            }
        }
    }

    for &(path_name, prefix) in POLICY_FORMS {
        for (macro_name, derive) in [
            ("grouped_sensitive", "Sensitive"),
            ("grouped_display", "Display"),
        ] {
            let item_name = format!("DetectorGroup{path_name}{derive}");
            cells.push(MatrixCell {
                id: item_name.clone(),
                semantic_descriptor: format!(
                    "id={item_name}|field=Type::Group(std::net::IpAddr)|policy={prefix}IpAddress|derive={derive}|macro={macro_name}"
                ),
                derive_line: source.lines().count() + 1,
            });
            source.push_str(&format!(
                "{macro_name}!({item_name}, std::net::IpAddr, {prefix}IpAddress);\n"
            ));
        }
    }

    source.push_str("fn main() {}\n");
    (source, cells)
}

fn positive_source() -> String {
    let mut source = "use safe::{IpAddress, Redactable, RedactableWithFormatter, RedactionPolicy, Secret, Sensitive, SensitiveDisplay};\n".to_owned();
    for &(identity, scalar) in SCALARS {
        source.push_str(&format!("type Alias{identity} = {scalar};\n"));
        for (path_name, policy) in [
            ("Short", "Secret".to_owned()),
            ("Renamed", "safe::Secret".to_owned()),
            ("Absolute", "::safe::Secret".to_owned()),
        ] {
            for (suffix, ty) in [
                ("Direct", scalar.to_owned()),
                ("Alias", format!("Alias{identity}")),
            ] {
                source.push_str(&format!(
                    "#[derive(Clone, Sensitive)] struct Secret{identity}{suffix}{path_name} {{ #[sensitive({policy})] value: {ty} }}\n"
                ));
                source.push_str(&format!(
                    "#[derive(SensitiveDisplay)] #[error(\"{{value:?}}\")] struct Secret{identity}{suffix}{path_name}Display {{ #[sensitive({policy})] value: {ty} }}\n"
                ));
            }
        }
    }
    for &(identity, ip) in IPS {
        for (path_name, policy) in [
            ("Short", "IpAddress"),
            ("Renamed", "safe::IpAddress"),
            ("Absolute", "::safe::IpAddress"),
        ] {
            source.push_str(&format!(
                "#[derive(Clone, Sensitive)] struct Ip{identity}{path_name} {{ #[sensitive({policy})] value: {ip} }}\n"
            ));
            source.push_str(&format!(
                "#[derive(SensitiveDisplay)] #[error(\"{{value:?}}\")] struct Ip{identity}{path_name}Display {{ #[sensitive({policy})] value: {ip} }}\n"
            ));
        }
    }
    source.push_str(
        r#"
mod custom {
    pub struct IpAddress;
    impl safe::RedactionPolicy for IpAddress {
        fn policy() -> safe::TextRedactionPolicy { safe::TextRedactionPolicy::keep_last(2) }
    }
}
#[derive(Clone, Sensitive)]
struct CustomMap { #[sensitive(custom::IpAddress)] value: std::collections::HashMap<std::net::IpAddr, String> }
use custom::IpAddress as CustomIpAddress;
#[derive(Clone, Sensitive)]
struct CustomMapShort { #[sensitive(CustomIpAddress)] value: std::collections::HashMap<std::net::IpAddr, String> }
#[derive(SensitiveDisplay)]
#[error("{value:?}")]
struct CustomMapDisplay { #[sensitive(custom::IpAddress)] value: std::collections::HashMap<std::net::IpAddr, String> }
#[derive(SensitiveDisplay)]
#[error("{value:?}")]
struct CustomMapShortDisplay { #[sensitive(CustomIpAddress)] value: std::collections::HashMap<std::net::IpAddr, String> }
#[derive(Clone, Sensitive)]
struct CustomBTreeMap { #[sensitive(custom::IpAddress)] value: std::collections::BTreeMap<std::net::IpAddr, String> }
#[derive(Clone, Sensitive)]
struct CustomBTreeMapShort { #[sensitive(CustomIpAddress)] value: std::collections::BTreeMap<std::net::IpAddr, String> }
#[derive(SensitiveDisplay)]
#[error("{value:?}")]
struct CustomBTreeMapDisplay { #[sensitive(custom::IpAddress)] value: std::collections::BTreeMap<std::net::IpAddr, String> }
#[derive(SensitiveDisplay)]
#[error("{value:?}")]
struct CustomBTreeMapShortDisplay { #[sensitive(CustomIpAddress)] value: std::collections::BTreeMap<std::net::IpAddr, String> }
#[derive(Clone, Sensitive)]
struct GenericMap<P: RedactionPolicy> { #[sensitive(P)] value: std::collections::HashMap<std::net::IpAddr, String>, marker: std::marker::PhantomData<P> }
#[derive(SensitiveDisplay)]
#[error("{value:?}")]
struct GenericMapDisplay<P: RedactionPolicy> { #[sensitive(P)] value: std::collections::HashMap<std::net::IpAddr, String>, marker: std::marker::PhantomData<P> }
#[derive(Clone, Sensitive)]
struct GenericBTreeMap<P: RedactionPolicy> { #[sensitive(P)] value: std::collections::BTreeMap<std::net::IpAddr, String>, marker: std::marker::PhantomData<P> }
#[derive(SensitiveDisplay)]
#[error("{value:?}")]
struct GenericBTreeMapDisplay<P: RedactionPolicy> { #[sensitive(P)] value: std::collections::BTreeMap<std::net::IpAddr, String>, marker: std::marker::PhantomData<P> }
#[derive(Clone, Sensitive)]
struct WrappedIp { value: Option<safe::SensitiveValue<std::net::IpAddr, safe::IpAddress>> }
#[derive(Clone, Sensitive)]
struct WrappedNestedIp { value: std::collections::HashMap<String, Result<safe::SensitiveValue<std::net::IpAddr, safe::IpAddress>, String>> }
fn main() {
    const CANARY: &str = "sensitive";
    let hash_key: std::net::IpAddr = "192.0.2.7".parse().unwrap();
    let values = std::collections::HashMap::from([(hash_key, CANARY.to_owned())]);
    let generic = GenericMap::<safe::IpAddress> { value: values.clone(), marker: std::marker::PhantomData }.redact();
    assert!(generic.value.contains_key(&hash_key));
    assert_eq!(generic.value[&hash_key], "*****tive");
    assert!(!generic.value[&hash_key].contains(CANARY));
    let display = GenericMapDisplay::<safe::IpAddress> { value: values.clone(), marker: std::marker::PhantomData };
    let rendered = display.redacted_display().to_string();
    assert_eq!(rendered, "{192.0.2.7: \"*****tive\"}");
    assert!(!rendered.contains(CANARY));
    let custom = CustomMap { value: values.clone() }.redact();
    assert!(custom.value.contains_key(&hash_key));
    assert_eq!(custom.value[&hash_key], "*******ve");
    assert!(!custom.value[&hash_key].contains(CANARY));
    let custom_short = CustomMapShort { value: values.clone() }.redact();
    assert_eq!(custom_short.value[&hash_key], "*******ve");
    let rendered = CustomMapDisplay { value: values.clone() }.redacted_display().to_string();
    assert_eq!(rendered, "{192.0.2.7: \"*******ve\"}");
    assert!(!rendered.contains(CANARY));
    let rendered = CustomMapShortDisplay { value: values }.redacted_display().to_string();
    assert_eq!(rendered, "{192.0.2.7: \"*******ve\"}");
    assert!(!rendered.contains(CANARY));

    let btree_key: std::net::IpAddr = "192.0.2.8".parse().unwrap();
    let btree_values = std::collections::BTreeMap::from([(btree_key, CANARY.to_owned())]);
    let generic_btree = GenericBTreeMap::<safe::IpAddress> { value: btree_values.clone(), marker: std::marker::PhantomData }.redact();
    assert!(generic_btree.value.contains_key(&btree_key));
    assert_eq!(generic_btree.value[&btree_key], "*****tive");
    assert!(!generic_btree.value[&btree_key].contains(CANARY));
    let generic_btree_display = GenericBTreeMapDisplay::<safe::IpAddress> { value: btree_values.clone(), marker: std::marker::PhantomData };
    let rendered = generic_btree_display.redacted_display().to_string();
    assert_eq!(rendered, "{192.0.2.8: \"*****tive\"}");
    assert!(!rendered.contains(CANARY));
    let custom_btree = CustomBTreeMap { value: btree_values.clone() }.redact();
    assert!(custom_btree.value.contains_key(&btree_key));
    assert_eq!(custom_btree.value[&btree_key], "*******ve");
    assert!(!custom_btree.value[&btree_key].contains(CANARY));
    let custom_btree_short = CustomBTreeMapShort { value: btree_values.clone() }.redact();
    assert_eq!(custom_btree_short.value[&btree_key], "*******ve");
    let rendered = CustomBTreeMapDisplay { value: btree_values.clone() }.redacted_display().to_string();
    assert_eq!(rendered, "{192.0.2.8: \"*******ve\"}");
    assert!(!rendered.contains(CANARY));
    let rendered = CustomBTreeMapShortDisplay { value: btree_values }.redacted_display().to_string();
    assert_eq!(rendered, "{192.0.2.8: \"*******ve\"}");
    assert!(!rendered.contains(CANARY));
}
"#,
    );
    source
}

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate has workspace parent")
        .join("target/phase02-policy-matrix")
}

fn write_fixture(directory: &Path, source: &str) {
    fs::create_dir_all(directory.join("src")).unwrap();
    let dependency = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::write(
        directory.join("Cargo.toml"),
        format!(
            "[package]\nname='phase02-policy-matrix'\nversion='0.0.0'\nedition='2024'\npublish=false\n[workspace]\n[dependencies]\nsafe={{package='redactable',path='{}',features=['ip-address']}}\n",
            dependency.display()
        ),
    )
    .unwrap();
    fs::write(directory.join("src/main.rs"), source).unwrap();
}

fn cargo_check(directory: &Path, json: bool) -> std::process::Output {
    let mut command = Command::new(env!("CARGO"));
    command
        .args(["check", "--offline", "--manifest-path"])
        .arg(directory.join("Cargo.toml"))
        .env("CARGO_TARGET_DIR", directory.join("target"));
    if json {
        command.args(["--message-format", "json"]);
    }
    command.output().expect("matrix cargo check runs")
}

fn cargo_run(directory: &Path) -> std::process::Output {
    Command::new(env!("CARGO"))
        .args(["run", "--offline", "--manifest-path"])
        .arg(directory.join("Cargo.toml"))
        .env("CARGO_TARGET_DIR", directory.join("target"))
        .output()
        .expect("positive matrix cargo run executes")
}

fn fingerprint(descriptors: impl IntoIterator<Item = String>) -> u64 {
    let mut descriptors: Vec<_> = descriptors.into_iter().collect();
    descriptors.sort_unstable();
    descriptors
        .into_iter()
        .fold(0xcbf29ce484222325, |hash, descriptor| {
            descriptor.bytes().chain([0xff]).fold(hash, |hash, byte| {
                (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
            })
        })
}

fn grid_fingerprint(cells: &[MatrixCell]) -> u64 {
    fingerprint(cells.iter().map(|cell| cell.semantic_descriptor.clone()))
}

fn positive_control_fingerprint() -> u64 {
    fingerprint(
        REQUIRED_POSITIVE_CONTROLS
            .iter()
            .map(|(id, definition, exercise)| {
                // The frozen descriptor captures identity, generated definition shape,
                // and exercise mode; changing any axis requires an audited update.
                format!("id={id}|definition={definition}|exercise={exercise}")
            }),
    )
}

fn validate_positive_source(source: &str) -> Result<(), String> {
    if REQUIRED_POSITIVE_CONTROLS.len() != EXPECTED_POSITIVE_CONTROLS {
        return Err("positive control cardinality changed".to_owned());
    }
    let control_fingerprint = positive_control_fingerprint();
    if control_fingerprint != EXPECTED_POSITIVE_FINGERPRINT {
        return Err(format!(
            "positive control descriptors changed: {control_fingerprint:#018x}"
        ));
    }
    let source_fingerprint = fingerprint([source.to_owned()]);
    if source_fingerprint != EXPECTED_POSITIVE_SOURCE_FINGERPRINT {
        return Err(format!(
            "canonical generated positive source changed: {source_fingerprint:#018x}"
        ));
    }
    for (id, definition, exercise) in REQUIRED_POSITIVE_CONTROLS {
        if source.match_indices(definition).count() != 1 {
            return Err(format!(
                "positive control {id} definition is missing or duplicated"
            ));
        }
        if source.match_indices(exercise).count() != 1 {
            return Err(format!(
                "positive control {id} exercise is missing or duplicated"
            ));
        }
    }
    Ok(())
}

#[test]
fn direct_only_policy_leaf_matrix_rejects_every_recursive_cell() {
    let directory = fixture_dir();
    let (negative, cells) = negative_source();
    let identities: HashSet<_> = cells.iter().map(|cell| cell.id.as_str()).collect();
    assert_eq!(cells.len(), EXPECTED_NEGATIVE_CELLS);
    assert_eq!(identities.len(), EXPECTED_NEGATIVE_CELLS);
    assert_eq!(
        grid_fingerprint(&cells),
        EXPECTED_GRID_FINGERPRINT,
        "matrix cell semantics changed; audit field/policy/derive/source axes before updating its fingerprint"
    );

    let positive_source = positive_source();
    validate_positive_source(&positive_source).expect("positive source contract must be intact");
    write_fixture(&directory, &positive_source);
    let positive = cargo_run(&directory);
    assert!(
        positive.status.success(),
        "positive/custom/generic controls failed:\n{}",
        String::from_utf8_lossy(&positive.stderr)
    );

    write_fixture(&directory, &negative);
    let output = cargo_check(&directory, true);
    assert!(
        !output.status.success(),
        "negative matrix unexpectedly compiled"
    );
    let error_lines: HashSet<_> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(compiler_error_lines)
        .flatten()
        .collect();
    for cell in cells {
        assert!(
            error_lines.contains(&cell.derive_line),
            "negative matrix cell {} on generated line {} has no attributable error-level diagnostic",
            cell.id,
            cell.derive_line
        );
    }
}

#[test]
fn matrix_integrity_fingerprints_detect_semantic_mutation_and_control_deletion() {
    let (_, cells) = negative_source();
    let original = grid_fingerprint(&cells);
    let mut mutated: Vec<_> = cells
        .iter()
        .map(|cell| cell.semantic_descriptor.clone())
        .collect();
    mutated[0].push_str("|mutant=changed-field-type");
    assert_ne!(original, fingerprint(mutated));

    let complete = positive_control_fingerprint();
    let shortened = fingerprint(REQUIRED_POSITIVE_CONTROLS[..11].iter().map(
        |(id, definition, exercise)| format!("id={id}|definition={definition}|exercise={exercise}"),
    ));
    assert_ne!(complete, shortened);

    let positive = positive_source();
    let btree_field = "struct GenericBTreeMap<P: RedactionPolicy> { #[sensitive(P)] value: std::collections::BTreeMap<std::net::IpAddr, String>";
    let hash_field = "struct GenericBTreeMap<P: RedactionPolicy> { #[sensitive(P)] value: std::collections::HashMap<std::net::IpAddr, String>";
    let btree_initializer = "GenericBTreeMap::<safe::IpAddress> { value: btree_values.clone()";
    let hash_initializer = "GenericBTreeMap::<safe::IpAddress> { value: values.clone()";
    assert!(positive.contains(btree_field));
    assert!(positive.contains(btree_initializer));
    let mutant = positive.replacen(btree_field, hash_field, 1).replacen(
        btree_initializer,
        hash_initializer,
        1,
    );
    assert!(
        validate_positive_source(&mutant).is_err(),
        "GenericBTreeMap-to-HashMap semantic mutant must fail the real positive gate"
    );
}
