//! Downstream policy leaves formatted by `SensitiveDisplay` templates.
//!
//! Every leaf implements the public `PolicyFormat` trait and
//! rides the same borrowed route as `String`: library containers forward to it,
//! so `Option<ManualLeaf>` or `HashMap<String, ManualLeaf>` needs no field option.

use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    fmt::{Debug, Formatter, Result as FmtResult},
    rc::Rc,
    sync::Arc,
};

use redactable::__private::DeclaredFormatting as LegacyDeclaredFormatting;
use redactable::PolicyDisplay as RenamedPolicyDisplay;
use redactable::policy::RecursivePolicyKind;
use redactable::{
    DeclaredFormatting, PolicyDebug, PolicyDisplay, PolicyFormat, PolicyFormattingOutput,
    RedactableMapper, RedactableWithFormatter, RedactionPolicy, Secret, SensitiveDisplay,
    SensitiveDual,
};

pub struct ReviewedFormatter;

impl RedactableWithFormatter for ReviewedFormatter {
    fn fmt_redacted(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter.write_str("[REDACTED]")
    }
}

impl DeclaredFormatting for ReviewedFormatter {}

pub fn require_legacy_declaration<T: LegacyDeclaredFormatting + ?Sized>(_: &T) {}

#[derive(SensitiveDisplay)]
#[error("{value}")]
pub struct ReviewedManualFormatting {
    pub value: ReviewedFormatter,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ManualLeaf(pub String);

impl PolicyFormat for ManualLeaf {
    type Output = String;

    fn apply_policy_for_formatting<P, M>(&self, _mapper: &M) -> PolicyFormattingOutput<String>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        PolicyFormattingOutput::Value(P::policy().apply_to(&self.0))
    }
}

#[derive(Debug)]
pub struct DownstreamBoxLeaf(pub String);

impl PolicyFormat for DownstreamBoxLeaf {
    type Output = String;

    fn apply_policy_for_formatting<P, M>(&self, _mapper: &M) -> PolicyFormattingOutput<String>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        PolicyFormattingOutput::Value(P::policy().apply_to(&self.0))
    }
}

#[derive(SensitiveDisplay)]
#[error("{value} {value:?}")]
pub struct DownstreamBoxFormatting {
    #[sensitive(Secret)]
    pub value: Box<DownstreamBoxLeaf>,
}

#[derive(Clone, Debug)]
pub struct LegacyOnlyLeaf(pub String);

impl PolicyFormat for LegacyOnlyLeaf {
    type Output = String;

    fn apply_policy_for_formatting<P, M>(&self, _mapper: &M) -> PolicyFormattingOutput<String>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        PolicyFormattingOutput::Value(P::policy().apply_to(&self.0))
    }
}

// `recursive` suppresses the inferred field bound; the declaration states it.
#[derive(SensitiveDisplay)]
#[error("{value}")]
pub struct CombinedLegacyRecursive<T>
where
    Option<T>: PolicyDisplay<Secret>,
{
    #[sensitive(Secret)]
    #[redactable(recursive)]
    pub value: Option<T>,
}

#[derive(Clone, serde::Serialize, SensitiveDual)]
#[error("{value}")]
pub struct CombinedLegacyRecursiveDual {
    #[sensitive(Secret)]
    #[redactable(recursive)]
    pub value: Option<String>,
}

macro_rules! legacy_formatting_case {
    ($display:ident, $debug:ident, $exercise:ident, $ty:ty, $value:expr) => {
        #[derive(SensitiveDisplay)]
        #[error("{value}")]
        struct $display {
            #[sensitive(Secret)]
            value: $ty,
        }

        #[derive(SensitiveDisplay)]
        #[error("{value:?}")]
        struct $debug {
            #[sensitive(Secret)]
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

impl PolicyFormat for CopyManualLeaf {
    type Output = u8;

    fn apply_policy_for_formatting<P, M>(&self, _mapper: &M) -> PolicyFormattingOutput<u8>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        let _ = self.0;
        PolicyFormattingOutput::Value(0)
    }
}

#[derive(SensitiveDisplay)]
#[error("{value}")]
pub struct LegacyCellDisplay {
    #[sensitive(Secret)]
    pub value: Cell<CopyManualLeaf>,
}

#[derive(SensitiveDisplay)]
#[error("{value:?}")]
pub struct LegacyCellDebug {
    #[sensitive(Secret)]
    pub value: Cell<CopyManualLeaf>,
}

#[derive(SensitiveDisplay)]
#[error("{value}")]
pub struct LegacyShapedPolicy {
    #[sensitive(redactable::Email)]
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
    T: PolicyDisplay<Secret>,
{
    #[sensitive(Secret)]
    pub leaf: T,
}

#[derive(SensitiveDisplay)]
#[error("{leaf:?}")]
pub struct GenericManualDebug<T>
where
    T: PolicyDebug<Secret>,
{
    #[sensitive(Secret)]
    pub leaf: T,
}

pub type Transparent<T> = T;

#[derive(SensitiveDisplay)]
#[error("{leaf}")]
pub struct RenamedMarker<T>
where
    T: RenamedPolicyDisplay<Secret>,
{
    #[sensitive(Secret)]
    pub leaf: T,
}

#[derive(SensitiveDisplay)]
#[error("{leaf}")]
pub struct TransparentMarker<T>
where
    T: RenamedPolicyDisplay<Secret>,
{
    #[sensitive(Secret)]
    pub leaf: Transparent<T>,
}
