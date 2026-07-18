use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    rc::Rc,
    sync::Arc,
};

use super::{PolicyApplicableRef, apply_policy, apply_policy_ref, redact};
use crate::{
    __private::{PolicyApplicableRefForGeneratedFormatting, PolicyFormattingOutput, PolicyMapper},
    RedactableMapper, RedactionPolicy, Secret, Sensitive,
    policy::RecursivePolicyKind,
};

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct SimulatedBorrowConflict {
    _non_zst: u8,
}

const SIMULATED_BORROW_CONFLICT: SimulatedBorrowConflict = SimulatedBorrowConflict { _non_zst: 0 };

impl PolicyApplicableRef for SimulatedBorrowConflict {
    type Output = &'static str;

    fn apply_policy_ref<P, M>(&self, _mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        "[REDACTED]"
    }
}

impl PolicyApplicableRefForGeneratedFormatting for SimulatedBorrowConflict {
    type FormattingOutput = &'static str;

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        _mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        PolicyFormattingOutput::Borrowed
    }
}

fn assert_formatting_conflict_propagates<T>(value: &T)
where
    T: PolicyApplicableRefForGeneratedFormatting,
{
    assert!(matches!(
        value.apply_policy_ref_for_generated_formatting::<Secret, _>(&PolicyMapper),
        PolicyFormattingOutput::Borrowed
    ));
}

#[test]
fn all_builtin_recursive_routes_propagate_formatting_conflicts() {
    assert_formatting_conflict_propagates(&Some(SIMULATED_BORROW_CONFLICT));
    assert_formatting_conflict_propagates(&vec![SIMULATED_BORROW_CONFLICT]);
    assert_formatting_conflict_propagates(&VecDeque::from([SIMULATED_BORROW_CONFLICT]));
    assert_formatting_conflict_propagates(&[SIMULATED_BORROW_CONFLICT]);
    assert_formatting_conflict_propagates(&Box::new(SIMULATED_BORROW_CONFLICT));
    assert_formatting_conflict_propagates(&Arc::new(SIMULATED_BORROW_CONFLICT));
    assert_formatting_conflict_propagates(&Rc::new(SIMULATED_BORROW_CONFLICT));
    assert_formatting_conflict_propagates(&RefCell::new(SIMULATED_BORROW_CONFLICT));
    assert_formatting_conflict_propagates(&Cell::new(SIMULATED_BORROW_CONFLICT));
    assert_formatting_conflict_propagates(&Result::<_, SimulatedBorrowConflict>::Ok(
        SIMULATED_BORROW_CONFLICT,
    ));
    assert_formatting_conflict_propagates(&Result::<SimulatedBorrowConflict, _>::Err(
        SIMULATED_BORROW_CONFLICT,
    ));
    assert_formatting_conflict_propagates(&HashMap::from([("key", SIMULATED_BORROW_CONFLICT)]));
    assert_formatting_conflict_propagates(&BTreeMap::from([("key", SIMULATED_BORROW_CONFLICT)]));
    assert_formatting_conflict_propagates(&HashSet::from([SIMULATED_BORROW_CONFLICT]));
    assert_formatting_conflict_propagates(&BTreeSet::from([SIMULATED_BORROW_CONFLICT]));
}

#[test]
fn redact_applies_policy() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct DefaultValue {
        #[sensitive(Secret)]
        value: String,
    }

    let value = DefaultValue {
        value: "top_secret".to_string(),
    };
    let redacted = redact(value);
    assert_eq!(redacted.value, "[REDACTED]");
}

#[test]
fn apply_policy_to_string() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Simple {
        #[sensitive(Secret)]
        value: String,
    }

    let s = Simple {
        value: "secret".into(),
    };
    let redacted = redact(s);
    assert_eq!(redacted.value, "[REDACTED]");
}

#[test]
fn apply_policy_to_option_string() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct WithOption {
        #[sensitive(Secret)]
        value: Option<String>,
    }

    let s = WithOption {
        value: Some("secret".into()),
    };
    let redacted = redact(s);
    assert_eq!(redacted.value, Some("[REDACTED]".into()));
}

#[test]
fn apply_policy_to_vec_string() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct WithVec {
        #[sensitive(Secret)]
        values: Vec<String>,
    }

    let s = WithVec {
        values: vec!["secret1".into(), "secret2".into()],
    };
    let redacted = redact(s);
    assert_eq!(redacted.values, vec!["[REDACTED]", "[REDACTED]"]);
}

#[test]
fn apply_policy_to_arc_string() {
    let value = Arc::new("secret".to_string());
    let redacted = apply_policy::<Secret, _>(value);
    assert_eq!(&*redacted, "[REDACTED]");
}

#[test]
fn apply_policy_to_nested_option_vec() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Nested {
        #[sensitive(Secret)]
        values: Option<Vec<String>>,
    }

    let s = Nested {
        values: Some(vec!["secret1".into(), "secret2".into()]),
    };
    let redacted = redact(s);
    assert_eq!(
        redacted.values,
        Some(vec!["[REDACTED]".into(), "[REDACTED]".into()])
    );
}

#[test]
fn apply_policy_to_nested_vec_option() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct Nested {
        #[sensitive(Secret)]
        values: Vec<Option<String>>,
    }

    let s = Nested {
        values: vec![Some("secret1".into()), None, Some("secret2".into())],
    };
    let redacted = redact(s);
    assert_eq!(
        redacted.values,
        vec![Some("[REDACTED]".into()), None, Some("[REDACTED]".into())]
    );
}

#[test]
fn apply_policy_to_deeply_nested() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct DeepNest {
        #[sensitive(Secret)]
        values: Option<Vec<Option<String>>>,
    }

    let s = DeepNest {
        values: Some(vec![Some("secret".into()), None]),
    };
    let redacted = redact(s);
    assert_eq!(redacted.values, Some(vec![Some("[REDACTED]".into()), None]));
}

#[test]
fn apply_policy_to_hashmap_values() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct WithMap {
        #[sensitive(Secret)]
        data: HashMap<String, String>,
    }

    let mut data = HashMap::new();
    data.insert("key1".into(), "secret1".into());
    data.insert("key2".into(), "secret2".into());

    let s = WithMap { data };
    let redacted = redact(s);

    // Keys preserved, values redacted
    assert!(redacted.data.contains_key("key1"));
    assert!(redacted.data.contains_key("key2"));
    assert_eq!(redacted.data.get("key1"), Some(&"[REDACTED]".to_string()));
    assert_eq!(redacted.data.get("key2"), Some(&"[REDACTED]".to_string()));
}

#[test]
fn apply_policy_to_nested_map_vec() {
    #[derive(Clone, Sensitive)]
    #[cfg_attr(feature = "slog", derive(serde::Serialize))]
    struct ComplexNest {
        #[sensitive(Secret)]
        data: HashMap<String, Vec<String>>,
    }

    let mut data = HashMap::new();
    data.insert("secrets".into(), vec!["secret1".into(), "secret2".into()]);

    let s = ComplexNest { data };
    let redacted = redact(s);

    assert_eq!(
        redacted.data.get("secrets"),
        Some(&vec!["[REDACTED]".to_string(), "[REDACTED]".to_string()])
    );
}

#[test]
fn apply_policy_ref_to_str() {
    let value = "secret";
    let redacted = apply_policy_ref::<Secret, _>(&value);
    assert_eq!(redacted, "[REDACTED]");
}

#[test]
fn apply_policy_ref_to_option_str() {
    let value: Option<&str> = Some("secret");
    let redacted = apply_policy_ref::<Secret, _>(&value);
    assert_eq!(redacted, Some("[REDACTED]".to_string()));
}
