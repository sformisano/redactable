use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

pub(crate) const EXPECTED_NEGATIVE_CELLS: usize = 938;
pub(crate) const EXPECTED_GRID_FINGERPRINT: u64 = 0x5fc6_befe_c3d9_4865;
const EXPECTED_POSITIVE_CONTROLS: usize = 8;
const EXPECTED_POSITIVE_FINGERPRINT: u64 = 0xa393_7d01_0e4c_a5c1;
const EXPECTED_POSITIVE_SOURCE_FINGERPRINT: u64 = 0xa3fc_8a96_1984_42ed;

pub(crate) const REQUIRED_POSITIVE_CONTROLS: &[(&str, &str, &str)] = &[
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
];

#[derive(Debug)]
pub(crate) struct MatrixCell {
    pub(crate) id: String,
    pub(crate) semantic_descriptor: String,
    pub(crate) first_line: usize,
    pub(crate) last_line: usize,
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
            format!(
                "std::collections::HashMap<{}, {leaf}>",
                if ip { "u8" } else { "String" }
            ),
        ),
        (
            "BTreeMapValue",
            format!(
                "std::collections::BTreeMap<{}, {leaf}>",
                if ip { "bool" } else { "String" }
            ),
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
        first_line: line,
        // A derive diagnostic may point at the derive itself or at the annotated
        // field whose generated expression fails. Keep attribution within this
        // generated item so one failing cell cannot satisfy a neighboring cell.
        last_line: if display { line + 2 } else { line + 1 },
    });
    if display {
        source.push_str(&format!(
            "#[derive(SensitiveDisplay)]\n#[error(\"{{value:?}}\")]\nstruct {name} {{ #[sensitive({policy})] value: {field_type} }}\n"
        ));
    } else {
        source.push_str(&format!(
            "#[derive(Clone, Sensitive, serde::Serialize)]\nstruct {name} {{ #[sensitive({policy})] #[serde(skip)] value: {field_type} }}\n"
        ));
    }
}

pub(crate) fn negative_source() -> (String, Vec<MatrixCell>) {
    let mut source = r#"use safe::{IpAddress, Redactable, RedactableWithFormatter, Secret, Sensitive, SensitiveDisplay};
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)] struct NegativeCustomMapKey(String);
type NegativeNestedTextKeyMap = Option<std::collections::HashMap<String, String>>;
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

        source.push_str(&format!("type NegativeIpAlias{identity} = {ip};\n"));
        let alias = format!("NegativeIpAlias{identity}");
        let alias_shapes = [
            ("NestedAlias", format!("Option<Vec<{alias}>>")),
            (
                "HashKeyAlias",
                format!("std::collections::HashMap<{alias}, String>"),
            ),
            (
                "BTreeKeyAlias",
                format!("std::collections::BTreeMap<{alias}, String>"),
            ),
            (
                "HashValueAlias",
                format!("std::collections::HashMap<u8, {alias}>"),
            ),
            (
                "BTreeValueAlias",
                format!("std::collections::BTreeMap<bool, {alias}>"),
            ),
            (
                "HashCompositeKeyAlias",
                format!("std::collections::HashMap<(u8, {alias}), String>"),
            ),
            (
                "BTreeCompositeKeyAlias",
                format!("std::collections::BTreeMap<(u8, {alias}), String>"),
            ),
            (
                "NestedHashAlias",
                format!("Option<std::collections::HashMap<{alias}, String>>"),
            ),
            (
                "NestedBTreeAlias",
                format!("Option<std::collections::BTreeMap<{alias}, String>>"),
            ),
        ];
        for (shape, field_type) in alias_shapes {
            for &(path_name, prefix) in POLICY_FORMS {
                for &(derive, display) in &[("Sensitive", false), ("Display", true)] {
                    push_reject(
                        &mut source,
                        &mut cells,
                        &format!("Ip{identity}{shape}{path_name}{derive}"),
                        &field_type,
                        &format!("{prefix}IpAddress"),
                        display,
                    );
                }
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

    for (shape, field_type) in [
        ("HashTextKey", "std::collections::HashMap<String, String>"),
        ("BTreeTextKey", "std::collections::BTreeMap<String, String>"),
        (
            "HashCustomKey",
            "std::collections::HashMap<NegativeCustomMapKey, String>",
        ),
        (
            "BTreeCustomKey",
            "std::collections::BTreeMap<NegativeCustomMapKey, String>",
        ),
        ("NestedTextKeyAlias", "NegativeNestedTextKeyMap"),
    ] {
        for &(path_name, prefix) in POLICY_FORMS {
            for &(derive, display) in &[("Sensitive", false), ("Display", true)] {
                push_reject(
                    &mut source,
                    &mut cells,
                    &format!("IpSafeKey{shape}{path_name}{derive}"),
                    field_type,
                    &format!("{prefix}IpAddress"),
                    display,
                );
            }
        }
    }

    push_generic_policy_rejections(&mut source, &mut cells);

    source.push_str("fn main() {}\n");
    (source, cells)
}

fn push_generic_policy_rejections(source: &mut String, cells: &mut Vec<MatrixCell>) {
    source.push_str(
        "#[derive(Clone, Sensitive, serde::Serialize)] struct GenericHashPolicy<P: safe::RedactionPolicy> { #[sensitive(P)] #[serde(skip)] value: std::collections::HashMap<std::net::IpAddr, String>, marker: std::marker::PhantomData<P> }\n",
    );
    source.push_str(
        "#[derive(SensitiveDisplay)] #[error(\"{value:?}\")] struct GenericHashPolicyDisplay<P: safe::RedactionPolicy> { #[sensitive(P)] value: std::collections::HashMap<std::net::IpAddr, String>, marker: std::marker::PhantomData<P> }\n",
    );
    source.push_str(
        "#[derive(Clone, Sensitive, serde::Serialize)] struct GenericTreePolicy<P: safe::RedactionPolicy> { #[sensitive(P)] #[serde(skip)] value: std::collections::BTreeMap<std::net::IpAddr, String>, marker: std::marker::PhantomData<P> }\n",
    );
    source.push_str(
        "#[derive(SensitiveDisplay)] #[error(\"{value:?}\")] struct GenericTreePolicyDisplay<P: safe::RedactionPolicy> { #[sensitive(P)] value: std::collections::BTreeMap<std::net::IpAddr, String>, marker: std::marker::PhantomData<P> }\n",
    );
    source.push_str(
        "#[derive(Clone, Sensitive, serde::Serialize)] struct GenericHashKey<K> { #[sensitive(safe::IpAddress)] #[serde(skip)] value: std::collections::HashMap<K, String> }\n",
    );
    source.push_str(
        "#[derive(SensitiveDisplay)] #[error(\"{value:?}\")] struct GenericHashKeyDisplay<K> { #[sensitive(safe::IpAddress)] value: std::collections::HashMap<K, String> }\n",
    );
    source.push_str(
        "#[derive(Clone, Sensitive, serde::Serialize)] struct GenericTreeKey<K> { #[sensitive(safe::IpAddress)] #[serde(skip)] value: std::collections::BTreeMap<K, String> }\n",
    );
    source.push_str(
        "#[derive(SensitiveDisplay)] #[error(\"{value:?}\")] struct GenericTreeKeyDisplay<K> { #[sensitive(safe::IpAddress)] value: std::collections::BTreeMap<K, String> }\n",
    );

    source.push_str("fn generic_rejections() {\n");
    for (id, exercise) in [
        (
            "GenericHashPolicyUse",
            "let _ = GenericHashPolicy::<safe::IpAddress> { value: std::collections::HashMap::new(), marker: std::marker::PhantomData }.redact();",
        ),
        (
            "GenericHashPolicyDisplayUse",
            "let _ = GenericHashPolicyDisplay::<safe::IpAddress> { value: std::collections::HashMap::new(), marker: std::marker::PhantomData }.redacted_display();",
        ),
        (
            "GenericTreePolicyUse",
            "let _ = GenericTreePolicy::<safe::IpAddress> { value: std::collections::BTreeMap::new(), marker: std::marker::PhantomData }.redact();",
        ),
        (
            "GenericTreePolicyDisplayUse",
            "let _ = GenericTreePolicyDisplay::<safe::IpAddress> { value: std::collections::BTreeMap::new(), marker: std::marker::PhantomData }.redacted_display();",
        ),
        (
            "GenericHashKeyUse",
            "let _ = GenericHashKey::<std::net::IpAddr> { value: std::collections::HashMap::new() }.redact();",
        ),
        (
            "GenericHashKeyDisplayUse",
            "let _ = GenericHashKeyDisplay::<std::net::IpAddr> { value: std::collections::HashMap::new() }.redacted_display();",
        ),
        (
            "GenericTreeKeyUse",
            "let _ = GenericTreeKey::<std::net::IpAddr> { value: std::collections::BTreeMap::new() }.redact();",
        ),
        (
            "GenericTreeKeyDisplayUse",
            "let _ = GenericTreeKeyDisplay::<std::net::IpAddr> { value: std::collections::BTreeMap::new() }.redacted_display();",
        ),
    ] {
        let line = source.lines().count() + 1;
        cells.push(MatrixCell {
            id: id.to_owned(),
            semantic_descriptor: format!("id={id}|generic-substitution=IpAddress|exercise"),
            first_line: line,
            last_line: line,
        });
        source.push_str(exercise);
        source.push('\n');
    }
    source.push_str("}\n");
}

pub(crate) fn positive_source() -> String {
    let mut source = "use safe::{IpAddress, Redactable, RedactableWithFormatter, Secret, Sensitive, SensitiveDisplay};\n".to_owned();
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
                    "#[derive(Clone, Sensitive, serde::Serialize)] struct Secret{identity}{suffix}{path_name} {{ #[sensitive({policy})] #[serde(skip)] value: {ty} }}\n"
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
                "#[derive(Clone, Sensitive, serde::Serialize)] struct Ip{identity}{path_name} {{ #[sensitive({policy})] #[serde(skip)] value: {ip} }}\n"
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
        type Kind = safe::TextPolicyKind;
        fn policy() -> safe::TextRedactionPolicy { safe::TextRedactionPolicy::keep_last(2) }
    }
}
#[derive(Clone, Sensitive, serde::Serialize)]
struct CustomMap { #[sensitive(custom::IpAddress)] #[serde(skip)] value: std::collections::HashMap<std::net::IpAddr, String> }
use custom::IpAddress as CustomIpAddress;
#[derive(Clone, Sensitive, serde::Serialize)]
struct CustomMapShort { #[sensitive(CustomIpAddress)] #[serde(skip)] value: std::collections::HashMap<std::net::IpAddr, String> }
#[derive(SensitiveDisplay)]
#[error("{value:?}")]
struct CustomMapDisplay { #[sensitive(custom::IpAddress)] value: std::collections::HashMap<std::net::IpAddr, String> }
#[derive(SensitiveDisplay)]
#[error("{value:?}")]
struct CustomMapShortDisplay { #[sensitive(CustomIpAddress)] value: std::collections::HashMap<std::net::IpAddr, String> }
#[derive(Clone, Sensitive, serde::Serialize)]
struct CustomBTreeMap { #[sensitive(custom::IpAddress)] #[serde(skip)] value: std::collections::BTreeMap<std::net::IpAddr, String> }
#[derive(Clone, Sensitive, serde::Serialize)]
struct CustomBTreeMapShort { #[sensitive(CustomIpAddress)] #[serde(skip)] value: std::collections::BTreeMap<std::net::IpAddr, String> }
#[derive(SensitiveDisplay)]
#[error("{value:?}")]
struct CustomBTreeMapDisplay { #[sensitive(custom::IpAddress)] value: std::collections::BTreeMap<std::net::IpAddr, String> }
#[derive(SensitiveDisplay)]
#[error("{value:?}")]
struct CustomBTreeMapShortDisplay { #[sensitive(CustomIpAddress)] value: std::collections::BTreeMap<std::net::IpAddr, String> }
#[derive(Clone, Sensitive, serde::Serialize)]
struct WrappedIp { #[serde(skip)] value: Option<safe::SensitiveValue<std::net::IpAddr, safe::IpAddress>> }
#[derive(Clone, Sensitive, serde::Serialize)]
struct WrappedNestedIp { #[serde(skip)] value: std::collections::HashMap<String, Result<safe::SensitiveValue<std::net::IpAddr, safe::IpAddress>, String>> }
fn main() {
    const CANARY: &str = "sensitive";
    let hash_key: std::net::IpAddr = "192.0.2.7".parse().unwrap();
    let values = std::collections::HashMap::from([(hash_key, CANARY.to_owned())]);
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

pub(crate) fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate has workspace parent")
        .join("target/phase02-policy-matrix")
}

pub(crate) fn write_fixture(directory: &Path, source: &str) {
    fs::create_dir_all(directory.join("src")).unwrap();
    let dependency = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::write(
        directory.join("Cargo.toml"),
        format!(
            "[package]\nname='phase02-policy-matrix'\nversion='0.0.0'\nedition='2024'\npublish=false\n[workspace]\n[dependencies]\nserde={{version='1',features=['derive']}}\nsafe={{package='redactable',path='{}',features={}}}\n",
            dependency.display(),
            if cfg!(feature = "slog") {
                "['ip-address','slog']"
            } else {
                "['ip-address']"
            }
        ),
    )
    .unwrap();
    fs::write(directory.join("src/main.rs"), source).unwrap();
}

pub(crate) fn cargo_check(directory: &Path, json: bool) -> std::process::Output {
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

pub(crate) fn cargo_run(directory: &Path) -> std::process::Output {
    Command::new(env!("CARGO"))
        .args(["run", "--offline", "--manifest-path"])
        .arg(directory.join("Cargo.toml"))
        .env("CARGO_TARGET_DIR", directory.join("target"))
        .output()
        .expect("positive matrix cargo run executes")
}

pub(crate) fn fingerprint(descriptors: impl IntoIterator<Item = String>) -> u64 {
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

pub(crate) fn grid_fingerprint(cells: &[MatrixCell]) -> u64 {
    fingerprint(cells.iter().map(|cell| cell.semantic_descriptor.clone()))
}

pub(crate) fn positive_control_fingerprint() -> u64 {
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

pub(crate) fn validate_positive_source(source: &str) -> Result<(), String> {
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
