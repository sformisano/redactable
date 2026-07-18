//! External-consumer regressions for policy-backed `RefCell` formatting.

use std::{
    cell::RefCell as StdRefCell,
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
    panic::AssertUnwindSafe,
    sync::Arc,
};

#[cfg(feature = "ip-address")]
use redactable::IpAddress;
use redactable::{
    PolicyApplicableRef, RedactableWithFormatter, RedactableWithMapper, RedactionPolicy, Secret,
    Sensitive, SensitiveDisplay, apply_policy_ref, redact,
};

const CANARY: &str = "followup-refcell-canary-7f21";

#[test]
fn public_free_redact_accepts_raw_structural_values() {
    assert_eq!(redact(CANARY.to_owned()), CANARY);
    assert_eq!(redact(vec![CANARY.to_owned()]), vec![CANARY.to_owned()]);
}

#[derive(Clone, Sensitive)]
struct ArcRefCellPolicyField {
    #[sensitive(Secret)]
    value: Arc<StdRefCell<String>>,
}

impl serde::Serialize for ArcRefCellPolicyField {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("arc-refcell-policy-field")
    }
}

#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn arc_refcell_policy_fields_build_and_redact_when_consumed() {
    let output = ArcRefCellPolicyField {
        value: Arc::new(StdRefCell::new(CANARY.to_owned())),
    }
    .redact_with(&redactable::__private::PolicyMapper);
    assert_eq!(&*output.value.borrow(), "[REDACTED]");
}

type CellAlias<T> = StdRefCell<T>;
type NestedCellAlias<T> = Option<CellAlias<T>>;
type OutputAlias<T> = <CellAlias<T> as PolicyApplicableRef>::Output;

fn apply_through_generic<T>(value: &CellAlias<T>) -> OutputAlias<T>
where
    T: PolicyApplicableRef,
{
    apply_policy_ref::<Secret, _>(value)
}

fn assert_refcell_output_contract<T>()
where
    T: PolicyApplicableRef,
    StdRefCell<T>: PolicyApplicableRef<Output = StdRefCell<T::Output>>,
{
}

#[test]
fn policy_applicable_ref_preserves_the_refcell_output_contract() {
    assert_refcell_output_contract::<String>();

    let source: CellAlias<String> = StdRefCell::new(CANARY.to_owned());
    let output: StdRefCell<String> = apply_through_generic(&source);

    assert_eq!(&*output.borrow(), "[REDACTED]");
    assert!(!output.borrow().contains(CANARY));
}

#[derive(SensitiveDisplay)]
#[error("{value} | {value:?}")]
struct NestedRefCellDisplay {
    #[sensitive(Secret)]
    value: Option<StdRefCell<String>>,
}

#[test]
fn nested_refcell_conflicts_propagate_through_recursive_policy_formatting() {
    let display = NestedRefCellDisplay {
        value: Some(StdRefCell::new(CANARY.to_owned())),
    };
    let mutable_borrow = display
        .value
        .as_ref()
        .expect("test value is present")
        .borrow_mut();

    let conflicted =
        std::panic::catch_unwind(AssertUnwindSafe(|| display.redacted_display().to_string()))
            .expect("nested policy formatting must not panic on a mutable borrow");
    assert_eq!(conflicted, "<borrowed> | <borrowed>");
    assert!(!conflicted.contains(CANARY));

    drop(mutable_borrow);
}

#[derive(SensitiveDisplay)]
#[error("{value} | {value:?}")]
struct GenericRefCellDisplay<T> {
    #[sensitive(Secret)]
    value: StdRefCell<T>,
}

#[test]
fn generated_formatting_handles_all_refcell_borrow_states_without_leaking() {
    let display = GenericRefCellDisplay {
        value: StdRefCell::new(CANARY.to_owned()),
    };

    let unborrowed = display.redacted_display().to_string();
    assert_eq!(unborrowed, "[REDACTED] | RefCell { value: \"[REDACTED]\" }");
    assert!(!unborrowed.contains(CANARY));

    let shared_borrow = display.value.borrow();
    let shared = display.redacted_display().to_string();
    assert_eq!(shared, "[REDACTED] | RefCell { value: \"[REDACTED]\" }");
    assert!(!shared.contains(CANARY));
    drop(shared_borrow);

    let mutable_borrow = display.value.borrow_mut();
    let conflicted =
        std::panic::catch_unwind(AssertUnwindSafe(|| display.redacted_display().to_string()))
            .expect("generated policy formatting must not panic on a mutable borrow");
    assert_eq!(conflicted, "<borrowed> | <borrowed>");
    assert!(!conflicted.contains(CANARY));
    drop(mutable_borrow);
}

#[derive(SensitiveDisplay)]
#[error("{value}")]
struct GenericPolicyRefCellDisplay<P: RedactionPolicy> {
    #[sensitive(P)]
    #[redactable(generated_formatting)]
    value: CellAlias<String>,
    marker: PhantomData<P>,
}

#[test]
fn generic_policy_instantiation_selects_conflict_safe_refcell_formatting() {
    let display = GenericPolicyRefCellDisplay::<Secret> {
        value: StdRefCell::new(CANARY.to_owned()),
        marker: PhantomData,
    };
    let mutable_borrow = display.value.borrow_mut();

    let conflicted =
        std::panic::catch_unwind(AssertUnwindSafe(|| display.redacted_display().to_string()))
            .expect("generic policy formatting must not panic on a mutable borrow");
    assert_eq!(conflicted, "<borrowed>");
    assert!(!conflicted.contains(CANARY));
    drop(mutable_borrow);
}

#[derive(SensitiveDisplay)]
enum GenericNestedRefCellDisplay<T> {
    #[error("{value}")]
    Value {
        #[sensitive(Secret)]
        value: NestedCellAlias<T>,
    },
}

#[test]
fn generic_nested_enum_selects_conflict_safe_refcell_formatting() {
    let display = GenericNestedRefCellDisplay::Value {
        value: Some(StdRefCell::new(CANARY.to_owned())),
    };
    let value = match &display {
        GenericNestedRefCellDisplay::Value { value } => value,
    }
    .as_ref()
    .expect("test value is present");
    let mutable_borrow = value.borrow_mut();

    let conflicted =
        std::panic::catch_unwind(AssertUnwindSafe(|| display.redacted_display().to_string()))
            .expect("generic nested enum formatting must not panic on a mutable borrow");
    assert_eq!(conflicted, "<borrowed>");
    assert!(!conflicted.contains(CANARY));
    drop(mutable_borrow);
}

type ConcreteCellAlias = StdRefCell<String>;

#[derive(SensitiveDisplay)]
#[error("{value}")]
struct ConcreteAliasRefCellDisplay {
    #[sensitive(Secret)]
    value: ConcreteCellAlias,
}

#[test]
fn concrete_refcell_alias_selects_conflict_safe_formatting() {
    let display = ConcreteAliasRefCellDisplay {
        value: StdRefCell::new(CANARY.to_owned()),
    };
    let mutable_borrow = display.value.borrow_mut();

    let conflicted =
        std::panic::catch_unwind(AssertUnwindSafe(|| display.redacted_display().to_string()))
            .expect("concrete alias formatting must not panic on a mutable borrow");
    assert_eq!(conflicted, "<borrowed>");
    assert!(!conflicted.contains(CANARY));
    drop(mutable_borrow);
}

#[derive(SensitiveDisplay)]
#[error("{value}")]
struct GenericNestedAliasPolicyDisplay<P: RedactionPolicy, T> {
    #[sensitive(P)]
    value: NestedCellAlias<T>,
    marker: PhantomData<P>,
}

fn assert_generic_nested_alias_borrow_conflict<P>()
where
    P: RedactionPolicy,
    GenericNestedAliasPolicyDisplay<P, String>: RedactableWithFormatter,
{
    let display = GenericNestedAliasPolicyDisplay::<P, String> {
        value: Some(StdRefCell::new(CANARY.to_owned())),
        marker: PhantomData,
    };
    let mutable_borrow = display
        .value
        .as_ref()
        .expect("test value is present")
        .borrow_mut();

    let conflicted =
        std::panic::catch_unwind(AssertUnwindSafe(|| display.redacted_display().to_string()))
            .expect("resolved generic alias formatting must not panic on a mutable borrow");
    assert_eq!(conflicted, "<borrowed>");
    assert!(!conflicted.contains(CANARY));
    drop(mutable_borrow);
}

#[test]
fn generic_nested_alias_resolves_under_secret_policy() {
    assert_generic_nested_alias_borrow_conflict::<Secret>();
}

#[derive(SensitiveDisplay)]
#[error("{values} | {values:?}")]
struct BorrowedBTreeMapKeyDisplay {
    #[sensitive(Secret)]
    values: BTreeMap<StdRefCell<String>, String>,
}

#[test]
fn btree_map_formatting_does_not_clone_a_mutably_borrowed_key() {
    let display = BorrowedBTreeMapKeyDisplay {
        values: BTreeMap::from([(StdRefCell::new(CANARY.to_owned()), CANARY.to_owned())]),
    };
    let mutable_borrow = display
        .values
        .keys()
        .next()
        .expect("test map contains one key")
        .borrow_mut();

    let rendered =
        std::panic::catch_unwind(AssertUnwindSafe(|| display.redacted_display().to_string()))
            .expect("BTreeMap formatting must not clone mutably borrowed keys");
    assert!(rendered.contains("<borrowed>"), "{rendered}");
    assert!(!rendered.contains(CANARY), "{rendered}");

    drop(mutable_borrow);
}

#[derive(SensitiveDisplay)]
#[error("{values}")]
struct NestedBorrowedMapDisplay {
    #[sensitive(Secret)]
    values: Option<BTreeMap<StdRefCell<String>, String>>,
}

#[derive(SensitiveDisplay)]
#[error("{values}")]
struct GenericBorrowedMapDisplay<T> {
    #[sensitive(Secret)]
    values: T,
}

#[derive(SensitiveDisplay)]
#[error("{values}")]
struct BoxedBorrowedMapKeyDisplay {
    #[sensitive(Secret)]
    values: BTreeMap<Box<StdRefCell<String>>, String>,
}

#[derive(SensitiveDisplay)]
#[error("{values}")]
struct ArcBorrowedMapDisplay {
    #[sensitive(Secret)]
    values: Arc<BTreeMap<StdRefCell<String>, String>>,
}

fn assert_borrowed_map_output<T>(display: &T, borrow: impl FnOnce())
where
    T: RedactableWithFormatter,
{
    let rendered =
        std::panic::catch_unwind(AssertUnwindSafe(|| display.redacted_display().to_string()))
            .expect("composed map formatting must not panic on a borrowed key");
    assert!(rendered.contains("<borrowed>"), "{rendered}");
    assert!(!rendered.contains(CANARY), "{rendered}");
    borrow();
}

#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn composed_map_shapes_format_keys_by_reference() {
    let nested = NestedBorrowedMapDisplay {
        values: Some(BTreeMap::from([(
            StdRefCell::new("public-key".to_owned()),
            CANARY.to_owned(),
        )])),
    };
    let nested_borrow = nested
        .values
        .as_ref()
        .unwrap()
        .keys()
        .next()
        .unwrap()
        .borrow_mut();
    assert_borrowed_map_output(&nested, || drop(nested_borrow));

    let generic = GenericBorrowedMapDisplay {
        values: BTreeMap::from([(StdRefCell::new("public-key".to_owned()), CANARY.to_owned())]),
    };
    let generic_borrow = generic.values.keys().next().unwrap().borrow_mut();
    assert_borrowed_map_output(&generic, || drop(generic_borrow));

    let boxed = BoxedBorrowedMapKeyDisplay {
        values: BTreeMap::from([(
            Box::new(StdRefCell::new("public-key".to_owned())),
            CANARY.to_owned(),
        )]),
    };
    let boxed_borrow = boxed.values.keys().next().unwrap().borrow_mut();
    assert_borrowed_map_output(&boxed, || drop(boxed_borrow));

    let arc = ArcBorrowedMapDisplay {
        values: Arc::new(BTreeMap::from([(
            StdRefCell::new("public-key".to_owned()),
            CANARY.to_owned(),
        )])),
    };
    let arc_borrow = arc.values.keys().next().unwrap().borrow_mut();
    assert_borrowed_map_output(&arc, || drop(arc_borrow));
}

#[derive(SensitiveDisplay)]
#[error("{values}")]
struct BorrowedSetDisplay {
    #[sensitive(Secret)]
    values: BTreeSet<StdRefCell<String>>,
}

#[test]
fn set_formatting_collects_back_and_collapses_duplicate_redactions() {
    let display = BorrowedSetDisplay {
        values: BTreeSet::from([
            StdRefCell::new("first".to_owned()),
            StdRefCell::new("second".to_owned()),
        ]),
    };
    assert_eq!(display.redacted_display().to_string(), "{[REDACTED]}");
}

#[cfg(feature = "ip-address")]
#[test]
fn generic_nested_alias_resolves_under_ip_address_policy() {
    assert_generic_nested_alias_borrow_conflict::<IpAddress>();
}

mod unrelated {
    use super::*;
    use redactable::{RedactableMapper, policy::RecursivePolicyKind};

    #[derive(Debug)]
    pub struct RefCell<T>(pub T);

    impl<T> PolicyApplicableRef for RefCell<T> {
        type Output = &'static str;

        fn apply_policy_ref<P, M>(&self, _mapper: &M) -> Self::Output
        where
            P: RedactionPolicy,
            P::Kind: RecursivePolicyKind,
            M: RedactableMapper,
        {
            let _ = &self.0;
            "custom-refcell"
        }
    }

    impl<T> redactable::__private::PolicyApplicableRefForGeneratedFormatting for RefCell<T> {
        type FormattingOutput = &'static str;

        fn apply_policy_ref_for_generated_formatting<P, M>(
            &self,
            mapper: &M,
        ) -> redactable::__private::PolicyFormattingOutput<Self::FormattingOutput>
        where
            P: RedactionPolicy,
            P::Kind: RecursivePolicyKind,
            M: RedactableMapper,
        {
            redactable::__private::PolicyFormattingOutput::Value(
                self.apply_policy_ref::<P, M>(mapper),
            )
        }
    }

    impl<T> redactable::__private::PolicyApplicableRefForFormatting for RefCell<T> {}
}

use unrelated::RefCell;
use unrelated::RefCell as RenamedRefCell;

#[derive(SensitiveDisplay)]
#[error("{value}")]
struct UnrelatedSameNameRefCellDisplay<T> {
    #[sensitive(Secret)]
    value: RefCell<T>,
}

#[derive(SensitiveDisplay)]
#[error("{value}")]
struct RenamedUnrelatedSameNameRefCellDisplay<T> {
    #[sensitive(Secret)]
    value: RenamedRefCell<T>,
}

#[test]
fn unrelated_same_named_refcell_uses_explicit_downstream_fallback() {
    let rendered = UnrelatedSameNameRefCellDisplay {
        value: RefCell(CANARY.to_owned()),
    }
    .redacted_display()
    .to_string();

    assert_eq!(rendered, "custom-refcell");
    assert!(!rendered.contains(CANARY));

    let renamed = RenamedUnrelatedSameNameRefCellDisplay {
        value: RenamedRefCell(CANARY.to_owned()),
    }
    .redacted_display()
    .to_string();
    assert_eq!(renamed, "custom-refcell");
    assert!(!renamed.contains(CANARY));
}
