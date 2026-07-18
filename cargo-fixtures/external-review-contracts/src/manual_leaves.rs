use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    rc::Rc,
    sync::Arc,
};

use redactable::__private::PolicyApplicableRefForFormatting as FormattingMarker;
use redactable::{
    RedactableMapper, RedactableWithFormatter, Secret, SensitiveDisplay, SensitiveDual,
};

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ManualLeaf(pub String);

impl redactable::PolicyApplicableRef for ManualLeaf {
    type Output = String;

    fn apply_policy_ref<P, M>(&self, _mapper: &M) -> Self::Output
    where
        P: redactable::RedactionPolicy,
        P::Kind: redactable::policy::RecursivePolicyKind,
        M: RedactableMapper,
    {
        P::policy().apply_to(&self.0)
    }
}

impl redactable::__private::PolicyApplicableRefForFormatting for ManualLeaf {}

#[derive(Debug)]
pub struct DownstreamBoxLeaf(pub String);

impl redactable::PolicyApplicableRef for DownstreamBoxLeaf {
    type Output = String;

    fn apply_policy_ref<P, M>(&self, _mapper: &M) -> Self::Output
    where
        P: redactable::RedactionPolicy,
        P::Kind: redactable::policy::RecursivePolicyKind,
        M: RedactableMapper,
    {
        P::policy().apply_to(&self.0)
    }
}

impl redactable::__private::PolicyApplicableRefForFormatting for Box<DownstreamBoxLeaf> {}

#[derive(SensitiveDisplay)]
#[error("{value} {value:?}")]
pub struct DownstreamBoxFormatting {
    #[sensitive(Secret)]
    pub value: Box<DownstreamBoxLeaf>,
}

#[derive(Clone, Debug)]
pub struct LegacyOnlyLeaf(pub String);

impl redactable::PolicyApplicableRef for LegacyOnlyLeaf {
    type Output = String;

    fn apply_policy_ref<P, M>(&self, _mapper: &M) -> Self::Output
    where
        P: redactable::RedactionPolicy,
        P::Kind: redactable::policy::RecursivePolicyKind,
        M: RedactableMapper,
    {
        P::policy().apply_to(&self.0)
    }
}

#[derive(SensitiveDisplay)]
#[error("{value}")]
pub struct CombinedLegacyRecursive<T> {
    #[sensitive(Secret)]
    #[redactable(recursive, legacy_formatting)]
    pub value: Option<T>,
}

#[derive(SensitiveDual)]
#[error("{value}")]
pub struct CombinedLegacyRecursiveDual {
    #[sensitive(Secret)]
    #[redactable(recursive, legacy_formatting)]
    pub value: Option<String>,
}

macro_rules! legacy_formatting_case {
    ($display:ident, $debug:ident, $exercise:ident, $ty:ty, $value:expr) => {
        #[derive(SensitiveDisplay)]
        #[error("{value}")]
        struct $display {
            #[sensitive(Secret)]
            #[redactable(legacy_formatting)]
            value: $ty,
        }

        #[derive(SensitiveDisplay)]
        #[error("{value:?}")]
        struct $debug {
            #[sensitive(Secret)]
            #[redactable(legacy_formatting)]
            value: $ty,
        }

        pub fn $exercise() {
            let value: $ty = $value;
            assert!(format!("{}", $display { value: value.clone() }.redacted_display())
                .contains("[REDACTED]"));
            assert!(format!("{}", $debug { value }.redacted_display()).contains("[REDACTED]"));
        }
    };
}

legacy_formatting_case!(
    LegacyOptionDisplay,
    LegacyOptionDebug,
    exercise_legacy_option,
    Option<ManualLeaf>,
    Some(ManualLeaf(String::from("secret")))
);
legacy_formatting_case!(
    LegacyBoxDisplay,
    LegacyBoxDebug,
    exercise_legacy_box,
    Box<ManualLeaf>,
    Box::new(ManualLeaf(String::from("secret")))
);
legacy_formatting_case!(
    LegacyVecDisplay,
    LegacyVecDebug,
    exercise_legacy_vec,
    Vec<ManualLeaf>,
    vec![ManualLeaf(String::from("secret"))]
);
legacy_formatting_case!(
    LegacyVecDequeDisplay,
    LegacyVecDequeDebug,
    exercise_legacy_vec_deque,
    VecDeque<ManualLeaf>,
    VecDeque::from([ManualLeaf(String::from("secret"))])
);
legacy_formatting_case!(
    LegacyArrayDisplay,
    LegacyArrayDebug,
    exercise_legacy_array,
    [ManualLeaf; 1],
    [ManualLeaf(String::from("secret"))]
);
legacy_formatting_case!(
    LegacyArcDisplay,
    LegacyArcDebug,
    exercise_legacy_arc,
    Arc<ManualLeaf>,
    Arc::new(ManualLeaf(String::from("secret")))
);
legacy_formatting_case!(
    LegacyRcDisplay,
    LegacyRcDebug,
    exercise_legacy_rc,
    Rc<ManualLeaf>,
    Rc::new(ManualLeaf(String::from("secret")))
);
legacy_formatting_case!(
    LegacyRefCellDisplay,
    LegacyRefCellDebug,
    exercise_legacy_ref_cell,
    RefCell<ManualLeaf>,
    RefCell::new(ManualLeaf(String::from("secret")))
);
legacy_formatting_case!(
    LegacyResultDisplay,
    LegacyResultDebug,
    exercise_legacy_result,
    Result<ManualLeaf, ManualLeaf>,
    Ok(ManualLeaf(String::from("secret")))
);
legacy_formatting_case!(
    LegacyHashMapDisplay,
    LegacyHashMapDebug,
    exercise_legacy_hash_map,
    HashMap<String, ManualLeaf>,
    HashMap::from([(String::from("key"), ManualLeaf(String::from("secret")))])
);
legacy_formatting_case!(
    LegacyBTreeMapDisplay,
    LegacyBTreeMapDebug,
    exercise_legacy_btree_map,
    BTreeMap<String, ManualLeaf>,
    BTreeMap::from([(String::from("key"), ManualLeaf(String::from("secret")))])
);
legacy_formatting_case!(
    LegacyHashSetDisplay,
    LegacyHashSetDebug,
    exercise_legacy_hash_set,
    HashSet<ManualLeaf>,
    HashSet::from([ManualLeaf(String::from("secret"))])
);
legacy_formatting_case!(
    LegacyBTreeSetDisplay,
    LegacyBTreeSetDebug,
    exercise_legacy_btree_set,
    BTreeSet<ManualLeaf>,
    BTreeSet::from([ManualLeaf(String::from("secret"))])
);

#[derive(Clone, Copy, Debug)]
pub struct CopyManualLeaf(pub u8);

impl redactable::PolicyApplicableRef for CopyManualLeaf {
    type Output = u8;

    fn apply_policy_ref<P, M>(&self, _mapper: &M) -> Self::Output
    where
        P: redactable::RedactionPolicy,
        P::Kind: redactable::policy::RecursivePolicyKind,
        M: RedactableMapper,
    {
        let _ = self.0;
        0
    }
}

impl redactable::__private::PolicyApplicableRefForFormatting for CopyManualLeaf {}

#[derive(SensitiveDisplay)]
#[error("{value}")]
pub struct LegacyCellDisplay {
    #[sensitive(Secret)]
    #[redactable(legacy_formatting)]
    pub value: std::cell::Cell<CopyManualLeaf>,
}

#[derive(SensitiveDisplay)]
#[error("{value:?}")]
pub struct LegacyCellDebug {
    #[sensitive(Secret)]
    #[redactable(legacy_formatting)]
    pub value: std::cell::Cell<CopyManualLeaf>,
}

#[derive(SensitiveDisplay)]
#[error("{value}")]
pub struct LegacyShapedPolicy {
    #[sensitive(redactable::Email)]
    #[redactable(legacy_formatting)]
    pub value: Option<ManualLeaf>,
}

#[derive(SensitiveDisplay)]
#[error("{leaf}")]
pub struct ManualFormatting {
    #[sensitive(Secret)]
    pub leaf: ManualLeaf,
}

#[derive(SensitiveDisplay)]
#[error("{leaf}")]
pub struct GenericManual<T>
where
    T: redactable::PolicyApplicableRef + redactable::__private::PolicyApplicableRefForFormatting,
{
    #[sensitive(Secret)]
    pub leaf: T,
}

#[derive(SensitiveDisplay)]
#[error("{leaf:?}")]
pub struct GenericManualDebug<T>
where
    T: redactable::PolicyApplicableRef + redactable::__private::PolicyApplicableRefForFormatting,
{
    #[sensitive(Secret)]
    pub leaf: T,
}

pub type Transparent<T> = T;

#[derive(SensitiveDisplay)]
#[error("{leaf}")]
pub struct RenamedMarker<T>
where
    T: redactable::PolicyApplicableRef + FormattingMarker,
{
    #[sensitive(Secret)]
    pub leaf: T,
}

#[derive(SensitiveDisplay)]
#[error("{leaf}")]
pub struct TransparentMarker<T>
where
    T: redactable::PolicyApplicableRef + FormattingMarker,
{
    #[sensitive(Secret)]
    pub leaf: Transparent<T>,
}
