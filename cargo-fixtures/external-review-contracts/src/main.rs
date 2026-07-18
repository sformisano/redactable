use std::boxed::Box as RenamedBox;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    marker::PhantomData,
    net::Ipv4Addr,
    sync::atomic::{AtomicUsize, Ordering},
};

use redactable::{
    IntoRedactedOutputExt, IpAddress, NotSensitiveDebug, Redactable, RedactableWithFormatter,
    Secret, ToRedactedOutput,
};

static RAW_SERIALIZATIONS: AtomicUsize = AtomicUsize::new(0);
static RAW_CLONES: AtomicUsize = AtomicUsize::new(0);
static RAW_DEBUGS: AtomicUsize = AtomicUsize::new(0);
static RAW_DISPLAYS: AtomicUsize = AtomicUsize::new(0);
static RAW_REDACTIONS: AtomicUsize = AtomicUsize::new(0);
static COMPACT_KEY_DEBUGS: AtomicUsize = AtomicUsize::new(0);
static ALTERNATE_KEY_DEBUGS: AtomicUsize = AtomicUsize::new(0);

mod explicit_recursion;
mod generated_formatting;
mod generic_policy;
mod key_formatting;
mod manual_leaves;
mod nodes;
mod non_clone;
mod observed;
mod public_api_boundary;
mod qualified;
mod qualified_nodes;
mod qualified_recursion;
mod qualified_same_name;
mod recursion_complements;

use generated_formatting::*;
use generic_policy::*;
use key_formatting::*;
use manual_leaves::*;
use nodes::*;
use non_clone::*;
use observed::*;
use qualified_nodes::*;

fn main() {
    assert_eq!(
        GenericPolicyScalar::<Secret> {
            value: 42,
            marker: PhantomData,
        }
        .redacted_display()
        .to_string(),
        "0 0"
    );
    assert_eq!(
        GenericPolicyIp::<IpAddress> {
            value: Ipv4Addr::new(192, 168, 10, 99),
            marker: PhantomData,
        }
        .redacted_display()
        .to_string(),
        "0.0.0.99 \"0.0.0.99\""
    );
    assert_eq!(
        GenericPolicyBox::<Secret> {
            value: Box::new("secret-canary".to_owned()),
            marker: PhantomData,
        }
        .redacted_display()
        .to_string(),
        "[REDACTED] \"[REDACTED]\""
    );
    assert_eq!(
        GenericPolicyBoxAlias::<Secret> {
            value: Box::new("secret-canary".to_owned()),
            marker: PhantomData,
        }
        .redacted_display()
        .to_string(),
        "[REDACTED] \"[REDACTED]\""
    );
    assert_eq!(
        GenericPolicyConcreteBox::<Secret> {
            value: Box::new("secret-canary".to_owned()),
            marker: PhantomData,
        }
        .redacted_display()
        .to_string(),
        "[REDACTED] \"[REDACTED]\""
    );
    assert_eq!(
        GenericPolicyRenamedBox::<Secret> {
            value: RenamedBox::new("secret-canary".to_owned()),
            marker: PhantomData,
        }
        .redacted_display()
        .to_string(),
        "[REDACTED] \"[REDACTED]\""
    );
    assert_eq!(
        GenericPolicyLocalLeaf::<Secret> {
            value: LocalLeaf(7),
            marker: PhantomData,
        }
        .redacted_display()
        .to_string(),
        "[REDACTED] \"[REDACTED]\""
    );
    for output in [
        GenericPolicyScalarAlias::<Secret> {
            value: 42,
            marker: PhantomData,
        }
        .redacted_display()
        .to_string(),
        GenericPolicyScalarRenamed::<Secret> {
            value: 42,
            marker: PhantomData,
        }
        .redacted_display()
        .to_string(),
        GenericPolicyScalarQualified::<Secret> {
            value: 42,
            marker: PhantomData,
        }
        .redacted_display()
        .to_string(),
        GenericPolicyScalarEnum::<Secret>::Alias {
            value: 42,
            marker: PhantomData,
        }
        .redacted_display()
        .to_string(),
        GenericPolicyScalarEnum::<Secret>::Renamed(42, PhantomData)
            .redacted_display()
            .to_string(),
    ] {
        assert_eq!(output, "0 0");
    }
    for output in [
        GenericPolicyIpAlias::<IpAddress> {
            value: Ipv4Addr::new(192, 168, 10, 99),
            marker: PhantomData,
        }
        .redacted_display()
        .to_string(),
        GenericPolicyIpRenamed::<IpAddress> {
            value: Ipv4Addr::new(192, 168, 10, 99),
            marker: PhantomData,
        }
        .redacted_display()
        .to_string(),
        GenericPolicyIpQualified::<IpAddress> {
            value: Ipv4Addr::new(192, 168, 10, 99),
            marker: PhantomData,
        }
        .redacted_display()
        .to_string(),
        GenericPolicyIpEnum::<IpAddress>::Alias {
            value: Ipv4Addr::new(192, 168, 10, 99),
            marker: PhantomData,
        }
        .redacted_display()
        .to_string(),
        GenericPolicyIpEnum::<IpAddress>::Renamed(Ipv4Addr::new(192, 168, 10, 99), PhantomData)
            .redacted_display()
            .to_string(),
    ] {
        assert_eq!(output, "0.0.0.99 \"0.0.0.99\"");
    }
    let event = ObservedEvent {
        value: Observed(String::from("raw-canary")),
    };
    static RECORD_STATIC: slog::RecordStatic<'static> =
        slog::record_static!(slog::Level::Info, "msg");
    let args = format_args!("msg");
    let record = slog::Record::new(&RECORD_STATIC, &args, slog::b!());
    slog::Value::serialize(&event, &record, "event", &mut CapturingSerializer).unwrap();
    assert_eq!(
        (
            RAW_CLONES.load(Ordering::SeqCst),
            RAW_DEBUGS.load(Ordering::SeqCst),
            RAW_DISPLAYS.load(Ordering::SeqCst),
            RAW_REDACTIONS.load(Ordering::SeqCst),
            RAW_SERIALIZATIONS.load(Ordering::SeqCst),
        ),
        (0, 0, 0, 0, 0)
    );

    let downstream_box = DownstreamBoxFormatting {
        value: Box::new(DownstreamBoxLeaf(String::from("secret"))),
    };
    assert_eq!(
        downstream_box.redacted_display().to_string(),
        "[REDACTED] \"[REDACTED]\""
    );

    let _ = Node { next: None }.redact();
    fn secret_recursive_node() -> SecretRecursiveNode {
        SecretRecursiveNode {
            secret: "recursive-secret-canary".to_owned(),
            next: Some(Box::new(SecretRecursiveNode {
                secret: "nested-recursive-secret-canary".to_owned(),
                next: None,
            })),
        }
    }
    let recursive_output = secret_recursive_node().redact();
    let recursive_output = format!("{recursive_output:?}");
    assert!(!recursive_output.contains("recursive-secret-canary"));
    assert!(!recursive_output.contains("nested-recursive-secret-canary"));

    // A `#[redactable(recursive)]` type through the consuming adapters. Both
    // calls were compile errors (`E0275`) before the owned-capability hierarchy
    // was deleted; the adapters now route through `.redact()`.
    let recursive_consuming = match secret_recursive_node().into_redacted_output() {
        redactable::RedactedOutput::Text(output) => output,
        other => panic!("structural output should be text, got {other:?}"),
    };
    assert!(recursive_consuming.contains("[REDACTED]"));
    assert!(!recursive_consuming.contains("recursive-secret-canary"));
    assert!(!recursive_consuming.contains("nested-recursive-secret-canary"));

    let recursive_slog =
        match redactable::slog::SlogRedactedExt::slog_redacted_json(secret_recursive_node())
            .to_redacted_output()
        {
            redactable::RedactedOutput::Json(output) => output.to_string(),
            other => panic!("slog JSON adapter should produce JSON output, got {other:?}"),
        };
    assert!(recursive_slog.contains("[REDACTED]"));
    assert!(!recursive_slog.contains("recursive-secret-canary"));
    assert!(!recursive_slog.contains("nested-recursive-secret-canary"));

    let recursive_enum_output = SecretRecursiveEnum::Next(Box::new(SecretRecursiveEnum::Secret(
        "recursive-enum-secret-canary".to_owned(),
    )))
    .redact();
    assert!(!format!("{recursive_enum_output:?}").contains("recursive-enum-secret-canary"));
    let _ = RecursiveEnum::Next(Box::new(RecursiveEnum::End)).redact();
    let _ = LeftEnum::Next(Box::new(RightEnum::End)).redact();
    let _ = RightEnum::Next(Box::new(LeftEnum::End)).redact();
    let _ = Left {
        right: Some(Box::new(Right { left: None })),
    }
    .redact();
    let _ = GenericNode {
        value: String::from("value"),
        next: None,
    }
    .redact();
    let _ = DisplayNode { next: None }.redacted_display().to_string();
    let _ = DisplayLeft {
        right: Some(Box::new(DisplayRight { left: None })),
    }
    .redacted_display()
    .to_string();
    let _ = DisplayEnum::Next(Box::new(DisplayEnum::End))
        .redacted_display()
        .to_string();
    let _ = DisplayLeftEnum::Next(Box::new(DisplayRightEnum::End))
        .redacted_display()
        .to_string();
    let _ = DisplayRightEnum::Next(Box::new(DisplayLeftEnum::End))
        .redacted_display()
        .to_string();
    let _ = DualNode { next: None }.redact();

    let mut records = HashMap::with_hasher(NonCloneBuildHasher);
    records.insert(NonCloneKey("key"), String::from("secret"));
    let formatted = format!("{}", NonCloneMap { records }.redacted_display());
    assert!(formatted.contains("[REDACTED]"));

    let ordered = BTreeSet::from([BTreeMap::from([(
        String::from("key"),
        String::from("secret"),
    )])]);
    assert!(
        format!(
            "{}",
            OrderedSetOfMaps { records: ordered }.redacted_display()
        )
        .contains("[REDACTED]")
    );

    let hashed = HashSet::from([BTreeMap::from([(
        String::from("key"),
        String::from("secret"),
    )])]);
    assert!(
        format!("{}", HashedSetOfMaps { records: hashed }.redacted_display())
            .contains("[REDACTED]")
    );

    assert_eq!(
        format!("{}", AliasedText { text: "secret" }.redacted_display()),
        "[REDACTED]"
    );
    assert_eq!(
        format!(
            "{}",
            ManualFormatting {
                leaf: ManualLeaf(String::from("secret"))
            }
            .redacted_display()
        ),
        "[REDACTED]"
    );
    assert_eq!(
        GenericManual {
            leaf: ManualLeaf(String::from("secret"))
        }
        .redacted_display()
        .to_string(),
        "[REDACTED]"
    );
    assert_eq!(
        GenericManualDebug {
            leaf: ManualLeaf(String::from("secret"))
        }
        .redacted_display()
        .to_string(),
        "\"[REDACTED]\""
    );
    assert_eq!(
        RenamedMarker {
            leaf: ManualLeaf(String::from("secret"))
        }
        .redacted_display()
        .to_string(),
        "[REDACTED]"
    );
    assert_eq!(
        TransparentMarker {
            leaf: ManualLeaf(String::from("secret"))
        }
        .redacted_display()
        .to_string(),
        "[REDACTED]"
    );
    qualified_recursion::exercise();
    recursion_complements::exercise();
    explicit_recursion::exercise();
    exercise_legacy_option();
    exercise_legacy_box();
    exercise_legacy_vec();
    exercise_legacy_vec_deque();
    exercise_legacy_array();
    exercise_legacy_arc();
    exercise_legacy_rc();
    exercise_legacy_ref_cell();
    exercise_legacy_result();
    exercise_legacy_hash_map();
    exercise_legacy_btree_map();
    exercise_legacy_hash_set();
    exercise_legacy_btree_set();
    assert_eq!(
        LegacyCellDisplay {
            value: std::cell::Cell::new(CopyManualLeaf(7)),
        }
        .redacted_display()
        .to_string(),
        "0"
    );
    assert_eq!(
        LegacyCellDebug {
            value: std::cell::Cell::new(CopyManualLeaf(7)),
        }
        .redacted_display()
        .to_string(),
        "Cell { value: 0 }"
    );
    assert_eq!(
        LegacyShapedPolicy {
            value: Some(ManualLeaf(String::from("alice@example.com"))),
        }
        .redacted_display()
        .to_string(),
        "Some(al***@example.com)"
    );
    assert_eq!(
        CombinedLegacyRecursive {
            value: Some(LegacyOnlyLeaf(String::from("secret"))),
        }
        .redacted_display()
        .to_string(),
        "Some([REDACTED])"
    );
    let combined_dual = CombinedLegacyRecursiveDual {
        value: Some(String::from("secret")),
    };
    assert_eq!(
        combined_dual.redacted_display().to_string(),
        "Some([REDACTED])"
    );
    let _ = combined_dual.redact();
    let _ = QualifiedNode {
        child: qualified::Node(String::from("secret")),
    }
    .redact();
    let _ = AliasQualifiedNode {
        child: qualified::Node(String::from("secret")),
    }
    .redact();
    qualified_same_name::exercise();
    let generated = GenericGenerated {
        value: RefCell::new(String::from("secret")),
    };
    let guard = generated.value.borrow_mut();
    assert_eq!(generated.redacted_display().to_string(), "<borrowed>");
    drop(guard);
    let generic_library = GenericLibraryFormatting {
        value: RefCell::new(String::from("secret")),
    };
    let generic_guard = generic_library.value.borrow_mut();
    assert_eq!(generic_library.redacted_display().to_string(), "<borrowed>");
    drop(generic_guard);
    let boxed_library = GenericLibraryFormatting {
        value: Box::new(RefCell::new(String::from("secret"))),
    };
    let boxed_guard = boxed_library.value.borrow_mut();
    assert_eq!(boxed_library.redacted_display().to_string(), "<borrowed>");
    drop(boxed_guard);

    COMPACT_KEY_DEBUGS.store(0, Ordering::SeqCst);
    ALTERNATE_KEY_DEBUGS.store(0, Ordering::SeqCst);
    let compact = format!(
        "{}",
        CompactMap {
            records: BTreeMap::from([(FlagKey, String::from("secret"))])
        }
        .redacted_display()
    );
    assert!(compact.contains("CompactKey"));
    assert!(!compact.contains("AlternateKey"));
    assert_eq!(COMPACT_KEY_DEBUGS.load(Ordering::SeqCst), 1);
    assert_eq!(ALTERNATE_KEY_DEBUGS.load(Ordering::SeqCst), 0);

    COMPACT_KEY_DEBUGS.store(0, Ordering::SeqCst);
    ALTERNATE_KEY_DEBUGS.store(0, Ordering::SeqCst);
    let alternate = format!(
        "{}",
        AlternateMap {
            records: BTreeMap::from([(FlagKey, String::from("secret"))])
        }
        .redacted_display()
    );
    assert!(alternate.contains("AlternateKey"));
    assert!(!alternate.contains("CompactKey"));
    assert_eq!(COMPACT_KEY_DEBUGS.load(Ordering::SeqCst), 0);
    assert_eq!(ALTERNATE_KEY_DEBUGS.load(Ordering::SeqCst), 1);

    COMPACT_KEY_DEBUGS.store(0, Ordering::SeqCst);
    ALTERNATE_KEY_DEBUGS.store(0, Ordering::SeqCst);
    let nested_compact_btree = NestedCompactBTreeMap {
        records: Some(vec![BTreeMap::from([(FlagKey, String::from("secret"))])]),
    };
    let compact = nested_compact_btree.redacted_display().to_string();
    assert!(compact.contains("CompactKey"));
    assert!(!compact.contains("AlternateKey"));
    assert_eq!(COMPACT_KEY_DEBUGS.load(Ordering::SeqCst), 1);
    assert_eq!(ALTERNATE_KEY_DEBUGS.load(Ordering::SeqCst), 0);

    COMPACT_KEY_DEBUGS.store(0, Ordering::SeqCst);
    ALTERNATE_KEY_DEBUGS.store(0, Ordering::SeqCst);
    let nested_alternate_btree = NestedAlternateBTreeMap {
        records: Some(vec![BTreeMap::from([(FlagKey, String::from("secret"))])]),
    };
    let alternate = nested_alternate_btree.redacted_display().to_string();
    assert!(alternate.contains("AlternateKey"));
    assert!(!alternate.contains("CompactKey"));
    assert_eq!(COMPACT_KEY_DEBUGS.load(Ordering::SeqCst), 0);
    assert_eq!(ALTERNATE_KEY_DEBUGS.load(Ordering::SeqCst), 1);

    COMPACT_KEY_DEBUGS.store(0, Ordering::SeqCst);
    ALTERNATE_KEY_DEBUGS.store(0, Ordering::SeqCst);
    let boxed_compact = BoxedCompactBTreeMap {
        records: Box::new(BTreeMap::from([(FlagKey, String::from("secret"))])),
    };
    let compact = boxed_compact.redacted_display().to_string();
    assert!(compact.contains("CompactKey"));
    assert!(!compact.contains("AlternateKey"));
    assert_eq!(COMPACT_KEY_DEBUGS.load(Ordering::SeqCst), 1);
    assert_eq!(ALTERNATE_KEY_DEBUGS.load(Ordering::SeqCst), 0);

    COMPACT_KEY_DEBUGS.store(0, Ordering::SeqCst);
    ALTERNATE_KEY_DEBUGS.store(0, Ordering::SeqCst);
    let boxed_alternate = BoxedAlternateBTreeMap {
        records: Box::new(BTreeMap::from([(FlagKey, String::from("secret"))])),
    };
    let alternate = boxed_alternate.redacted_display().to_string();
    assert!(alternate.contains("AlternateKey"));
    assert!(!alternate.contains("CompactKey"));
    assert_eq!(COMPACT_KEY_DEBUGS.load(Ordering::SeqCst), 0);
    assert_eq!(ALTERNATE_KEY_DEBUGS.load(Ordering::SeqCst), 1);

    COMPACT_KEY_DEBUGS.store(0, Ordering::SeqCst);
    ALTERNATE_KEY_DEBUGS.store(0, Ordering::SeqCst);
    let mut compact_hash_records = HashMap::with_hasher(NonCloneBuildHasher);
    compact_hash_records.insert(FlagKey, String::from("secret"));
    let nested_compact_hash = NestedCompactHashMap {
        records: Some(vec![compact_hash_records]),
    };
    let compact = nested_compact_hash.redacted_display().to_string();
    assert!(compact.contains("CompactKey"));
    assert!(!compact.contains("AlternateKey"));
    assert_eq!(COMPACT_KEY_DEBUGS.load(Ordering::SeqCst), 1);
    assert_eq!(ALTERNATE_KEY_DEBUGS.load(Ordering::SeqCst), 0);

    COMPACT_KEY_DEBUGS.store(0, Ordering::SeqCst);
    ALTERNATE_KEY_DEBUGS.store(0, Ordering::SeqCst);
    let mut alternate_hash_records = HashMap::with_hasher(NonCloneBuildHasher);
    alternate_hash_records.insert(FlagKey, String::from("secret"));
    let nested_alternate_hash = NestedAlternateHashMap {
        records: Some(vec![alternate_hash_records]),
    };
    let alternate = nested_alternate_hash.redacted_display().to_string();
    assert!(alternate.contains("AlternateKey"));
    assert!(!alternate.contains("CompactKey"));
    assert_eq!(COMPACT_KEY_DEBUGS.load(Ordering::SeqCst), 0);
    assert_eq!(ALTERNATE_KEY_DEBUGS.load(Ordering::SeqCst), 1);

    COMPACT_KEY_DEBUGS.store(0, Ordering::SeqCst);
    ALTERNATE_KEY_DEBUGS.store(0, Ordering::SeqCst);
    let borrowed = NestedBorrowedBTreeMap {
        records: Some(vec![BTreeMap::from([(
            FlagKey,
            RefCell::new(String::from("secret")),
        )])]),
    };
    let guard = borrowed.records.as_ref().unwrap()[0]
        .values()
        .next()
        .unwrap()
        .borrow_mut();
    assert_eq!(borrowed.redacted_display().to_string(), "<borrowed>");
    assert_eq!(COMPACT_KEY_DEBUGS.load(Ordering::SeqCst), 0);
    assert_eq!(ALTERNATE_KEY_DEBUGS.load(Ordering::SeqCst), 0);
    drop(guard);

    let borrowed_map = BTreeMap::from([(String::from("key"), String::from("secret"))]);
    let borrowed_map_output: BTreeMap<String, String> =
        redactable::apply_policy_ref::<Secret, _>(&borrowed_map);
    assert_eq!(borrowed_map_output["key"], "[REDACTED]");

    assert_eq!(format!("{:?}", NotSensitiveDebug("public")), "\"public\"");

    public_api_boundary::exercise();
}
