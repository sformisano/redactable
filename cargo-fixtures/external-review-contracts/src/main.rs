use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    fmt,
    hash::{BuildHasher, Hasher},
    marker::PhantomData,
    net::Ipv4Addr,
    rc::Rc,
    sync::Arc,
    sync::atomic::{AtomicUsize, Ordering},
};
use std::net::Ipv4Addr as RenamedPeer;
use std::primitive::u32 as RenamedCount;
use std::boxed::Box as RenamedBox;

use redactable::{
    IntoRedactedOutputExt, IpAddress, NotSensitiveDebug, Redactable, RedactableMapper,
    RedactableWithFormatter, RedactableWithMapper, RedactionPolicy, Secret, Sensitive,
    SensitiveDisplay, SensitiveDual, ToRedactedOutput,
};
use redactable::__private::PolicyApplicableRefForFormatting as FormattingMarker;
use serde::Serialize;

static RAW_SERIALIZATIONS: AtomicUsize = AtomicUsize::new(0);
static RAW_CLONES: AtomicUsize = AtomicUsize::new(0);
static RAW_DEBUGS: AtomicUsize = AtomicUsize::new(0);
static RAW_DISPLAYS: AtomicUsize = AtomicUsize::new(0);
static RAW_REDACTIONS: AtomicUsize = AtomicUsize::new(0);
static COMPACT_KEY_DEBUGS: AtomicUsize = AtomicUsize::new(0);
static ALTERNATE_KEY_DEBUGS: AtomicUsize = AtomicUsize::new(0);

type Count = u32;
type Peer = Ipv4Addr;
type BoxAlias<T> = Box<T>;
type ConcreteBox = Box<String>;

#[derive(SensitiveDisplay)]
#[error("{value} {value:?}")]
struct GenericPolicyScalar<P: RedactionPolicy> {
    #[sensitive(P)]
    value: u32,
    marker: PhantomData<P>,
}

#[derive(SensitiveDisplay)]
#[error("{value} {value:?}")]
struct GenericPolicyIp<P: RedactionPolicy> {
    #[sensitive(P)]
    value: Ipv4Addr,
    marker: PhantomData<P>,
}

#[derive(SensitiveDisplay)]
#[error("{value} {value:?}")]
struct GenericPolicyBox<P: RedactionPolicy> {
    #[sensitive(P)]
    #[redactable(generated_formatting)]
    value: Box<String>,
    marker: PhantomData<P>,
}

#[derive(SensitiveDisplay)]
#[error("{value} {value:?}")]
struct GenericPolicyBoxAlias<P: RedactionPolicy> {
    #[sensitive(P)]
    #[redactable(generated_formatting)]
    value: BoxAlias<String>,
    marker: PhantomData<P>,
}

#[derive(SensitiveDisplay)]
#[error("{value} {value:?}")]
struct GenericPolicyConcreteBox<P: RedactionPolicy> {
    #[sensitive(P)]
    #[redactable(generated_formatting)]
    value: ConcreteBox,
    marker: PhantomData<P>,
}

#[derive(SensitiveDisplay)]
#[error("{value} {value:?}")]
struct GenericPolicyRenamedBox<P: RedactionPolicy> {
    #[sensitive(P)]
    #[redactable(generated_formatting)]
    value: RenamedBox<String>,
    marker: PhantomData<P>,
}

struct LocalLeaf<T>(T);

impl redactable::PolicyApplicableRef for LocalLeaf<u8> {
    type Output = String;

    fn apply_policy_ref<P, M>(&self, _mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: redactable::policy::RecursivePolicyKind,
        M: RedactableMapper,
    {
        P::policy().apply_to(&self.0.to_string())
    }
}

impl FormattingMarker for LocalLeaf<u8> {}

impl fmt::Debug for LocalLeaf<u8> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(SensitiveDisplay)]
#[error("{value} {value:?}")]
struct GenericPolicyLocalLeaf<P: RedactionPolicy> {
    #[sensitive(P)]
    value: LocalLeaf<u8>,
    marker: PhantomData<P>,
}

macro_rules! generic_policy_scalar_shape {
    ($name:ident, $ty:ty) => {
        #[derive(SensitiveDisplay)]
        #[error("{value} {value:?}")]
        struct $name<P: RedactionPolicy> {
            #[sensitive(P)]
            value: $ty,
            marker: PhantomData<P>,
        }
    };
}

generic_policy_scalar_shape!(GenericPolicyScalarAlias, Count);
generic_policy_scalar_shape!(GenericPolicyScalarRenamed, RenamedCount);
generic_policy_scalar_shape!(GenericPolicyScalarQualified, std::primitive::u32);

macro_rules! generic_policy_ip_shape {
    ($name:ident, $ty:ty) => {
        #[derive(SensitiveDisplay)]
        #[error("{value} {value:?}")]
        struct $name<P: RedactionPolicy> {
            #[sensitive(P)]
            value: $ty,
            marker: PhantomData<P>,
        }
    };
}

generic_policy_ip_shape!(GenericPolicyIpAlias, Peer);
generic_policy_ip_shape!(GenericPolicyIpRenamed, RenamedPeer);
generic_policy_ip_shape!(GenericPolicyIpQualified, std::net::Ipv4Addr);

#[derive(SensitiveDisplay)]
enum GenericPolicyScalarEnum<P: RedactionPolicy> {
    #[error("{value} {value:?}")]
    Alias {
        #[sensitive(P)]
        value: Count,
        marker: PhantomData<P>,
    },
    #[error("{0} {0:?}")]
    Renamed(#[sensitive(P)] RenamedCount, PhantomData<P>),
}

#[derive(SensitiveDisplay)]
enum GenericPolicyIpEnum<P: RedactionPolicy> {
    #[error("{value} {value:?}")]
    Alias {
        #[sensitive(P)]
        value: Peer,
        marker: PhantomData<P>,
    },
    #[error("{0} {0:?}")]
    Renamed(#[sensitive(P)] RenamedPeer, PhantomData<P>),
}

struct Observed(String);

impl Clone for Observed {
    fn clone(&self) -> Self {
        RAW_CLONES.fetch_add(1, Ordering::SeqCst);
        Self(self.0.clone())
    }
}

impl fmt::Debug for Observed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        RAW_DEBUGS.fetch_add(1, Ordering::SeqCst);
        formatter.debug_tuple("Observed").field(&self.0).finish()
    }
}

impl fmt::Display for Observed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        RAW_DISPLAYS.fetch_add(1, Ordering::SeqCst);
        formatter.write_str(&self.0)
    }
}

impl Serialize for Observed {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        RAW_SERIALIZATIONS.fetch_add(1, Ordering::SeqCst);
        serializer.serialize_str(&self.0)
    }
}

impl RedactableWithMapper for Observed {
    fn redact_with<M: RedactableMapper>(mut self, mapper: &M) -> Self {
        RAW_REDACTIONS.fetch_add(1, Ordering::SeqCst);
        self.0 = mapper.map_sensitive::<_, Secret>(self.0);
        self
    }
}

#[derive(Sensitive)]
struct ObservedEvent {
    value: Observed,
}

struct CapturingSerializer;

impl slog::Serializer for CapturingSerializer {
    fn emit_arguments(
        &mut self,
        _key: slog::Key,
        _value: &fmt::Arguments<'_>,
    ) -> slog::Result {
        Ok(())
    }

    fn emit_serde(&mut self, _key: slog::Key, _value: &dyn slog::SerdeValue) -> slog::Result {
        Ok(())
    }
}

#[derive(Sensitive)]
struct Node {
    next: Option<Box<Node>>,
}

#[derive(Sensitive)]
enum RecursiveEnum {
    Next(Box<RecursiveEnum>),
    End,
}

// `#[redactable(recursive)]` combined with a `#[sensitive(Secret)]` field.
// Both the borrowed route (`.redact()`) and the consuming adapters are
// exercised below. The consuming route used to be a compile error for this
// shape: the removed owned-capability hierarchy generated an owned traversal
// bound that did not honor the override, forming a trait-solver cycle
// (`E0275`). The adapters now route through `.redact()`, which honors it, so
// recursive types are supported on every route.
#[derive(Sensitive, Serialize)]
struct SecretRecursiveNode {
    #[sensitive(Secret)]
    secret: String,
    #[redactable(recursive)]
    next: Option<Box<SecretRecursiveNode>>,
}

#[derive(Sensitive)]
enum SecretRecursiveEnum {
    Next(#[redactable(recursive)] Box<SecretRecursiveEnum>),
    Secret(#[sensitive(Secret)] String),
}

#[derive(Sensitive)]
enum LeftEnum {
    Next(Box<RightEnum>),
    End,
}

#[derive(Sensitive)]
enum RightEnum {
    Next(Box<LeftEnum>),
    End,
}

#[derive(Sensitive)]
struct Left {
    right: Option<Box<Right>>,
}

#[derive(Sensitive)]
struct Right {
    left: Option<Box<Left>>,
}

#[derive(Sensitive)]
struct GenericNode<T> {
    value: T,
    next: Option<Box<GenericNode<T>>>,
}

#[derive(SensitiveDisplay)]
#[error("node {next:?}")]
struct DisplayNode {
    next: Option<Box<DisplayNode>>,
}

#[derive(SensitiveDisplay)]
#[error("left {right:?}")]
struct DisplayLeft {
    right: Option<Box<DisplayRight>>,
}

#[derive(SensitiveDisplay)]
#[error("right {left:?}")]
struct DisplayRight {
    left: Option<Box<DisplayLeft>>,
}

#[derive(SensitiveDisplay)]
enum DisplayEnum {
    #[error("next {0:?}")]
    Next(Box<DisplayEnum>),
    #[error("end")]
    End,
}

#[derive(SensitiveDisplay)]
enum DisplayLeftEnum {
    #[error("next {0:?}")]
    Next(Box<DisplayRightEnum>),
    #[error("end")]
    End,
}

#[derive(SensitiveDisplay)]
enum DisplayRightEnum {
    #[error("next {0:?}")]
    Next(Box<DisplayLeftEnum>),
    #[error("end")]
    End,
}

#[derive(SensitiveDual)]
#[error("dual {next:?}")]
struct DualNode {
    next: Option<Box<DualNode>>,
}

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct NonCloneKey(&'static str);

#[derive(Default)]
struct NonCloneHasher;

impl Hasher for NonCloneHasher {
    fn finish(&self) -> u64 {
        0
    }

    fn write(&mut self, _bytes: &[u8]) {}
}

struct NonCloneBuildHasher;

impl BuildHasher for NonCloneBuildHasher {
    type Hasher = NonCloneHasher;

    fn build_hasher(&self) -> Self::Hasher {
        NonCloneHasher
    }
}

#[derive(SensitiveDisplay)]
#[error("{records:#?}")]
struct NonCloneMap {
    #[sensitive(Secret)]
    records: HashMap<NonCloneKey, String, NonCloneBuildHasher>,
}

#[derive(SensitiveDisplay)]
#[error("{records:?}")]
struct OrderedSetOfMaps {
    #[sensitive(Secret)]
    records: BTreeSet<BTreeMap<String, String>>,
}

#[derive(SensitiveDisplay)]
#[error("{records:?}")]
struct HashedSetOfMaps {
    #[sensitive(Secret)]
    records: HashSet<BTreeMap<String, String>>,
}

type Text<'a> = &'a str;

#[derive(SensitiveDisplay)]
#[error("{text}")]
struct AliasedText<'a> {
    #[sensitive(Secret)]
    text: Text<'a>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct ManualLeaf(String);

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
struct DownstreamBoxLeaf(String);

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
struct DownstreamBoxFormatting {
    #[sensitive(Secret)]
    value: Box<DownstreamBoxLeaf>,
}

#[derive(Clone, Debug)]
struct LegacyOnlyLeaf(String);

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
struct CombinedLegacyRecursive<T> {
    #[sensitive(Secret)]
    #[redactable(recursive, legacy_formatting)]
    value: Option<T>,
}

#[derive(SensitiveDual)]
#[error("{value}")]
struct CombinedLegacyRecursiveDual {
    #[sensitive(Secret)]
    #[redactable(recursive, legacy_formatting)]
    value: Option<String>,
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

        fn $exercise() {
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
struct CopyManualLeaf(u8);

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
struct LegacyCellDisplay {
    #[sensitive(Secret)]
    #[redactable(legacy_formatting)]
    value: std::cell::Cell<CopyManualLeaf>,
}

#[derive(SensitiveDisplay)]
#[error("{value:?}")]
struct LegacyCellDebug {
    #[sensitive(Secret)]
    #[redactable(legacy_formatting)]
    value: std::cell::Cell<CopyManualLeaf>,
}

#[derive(SensitiveDisplay)]
#[error("{value}")]
struct LegacyShapedPolicy {
    #[sensitive(redactable::Email)]
    #[redactable(legacy_formatting)]
    value: Option<ManualLeaf>,
}

#[derive(SensitiveDisplay)]
#[error("{leaf}")]
struct ManualFormatting {
    #[sensitive(Secret)]
    leaf: ManualLeaf,
}

#[derive(SensitiveDisplay)]
#[error("{leaf}")]
struct GenericManual<T>
where
    T: redactable::PolicyApplicableRef
        + redactable::__private::PolicyApplicableRefForFormatting,
{
    #[sensitive(Secret)]
    leaf: T,
}

#[derive(SensitiveDisplay)]
#[error("{leaf:?}")]
struct GenericManualDebug<T>
where
    T: redactable::PolicyApplicableRef
        + redactable::__private::PolicyApplicableRefForFormatting,
{
    #[sensitive(Secret)]
    leaf: T,
}

type Transparent<T> = T;

#[derive(SensitiveDisplay)]
#[error("{leaf}")]
struct RenamedMarker<T>
where
    T: redactable::PolicyApplicableRef + FormattingMarker,
{
    #[sensitive(Secret)]
    leaf: T,
}

#[derive(SensitiveDisplay)]
#[error("{leaf}")]
struct TransparentMarker<T>
where
    T: redactable::PolicyApplicableRef + FormattingMarker,
{
    #[sensitive(Secret)]
    leaf: Transparent<T>,
}

#[derive(SensitiveDisplay)]
#[error("{value}")]
struct GenericLibraryFormatting<T> {
    #[sensitive(Secret)]
    value: T,
}

mod qualified_recursion {
    use redactable::{Redactable, RedactableWithFormatter, Sensitive, SensitiveDisplay, SensitiveDual};

    #[derive(Sensitive)]
    pub struct SelfNode<T> {
        value: T,
        next: Option<Box<self::SelfNode<T>>>,
    }

    #[derive(SensitiveDisplay)]
    #[error("self {value:?} {next:?}")]
    pub struct SelfDisplayNode<T> {
        value: T,
        next: Option<Box<self::SelfDisplayNode<T>>>,
    }

    #[derive(SensitiveDual)]
    #[error("dual {value:?} {next:?}")]
    pub struct SelfDualNode<T> {
        value: T,
        next: Option<Box<self::SelfDualNode<T>>>,
    }

    pub mod tree {
        use redactable::{Redactable, RedactableWithFormatter, Sensitive, SensitiveDisplay};

        #[derive(Sensitive)]
        pub enum Tree<T> {
            Branch(T, Box<self::Tree<T>>),
            Leaf(T),
        }

        #[derive(SensitiveDisplay)]
        pub enum DisplayTree<T> {
            #[error("branch {0:?} {1:?}")]
            Branch(T, Box<self::DisplayTree<T>>),
            #[error("leaf {0:?}")]
            Leaf(T),
        }

        pub fn exercise() {
            let _ = Tree::Branch(
                String::from("secret"),
                Box::new(Tree::Leaf(String::from("secret"))),
            )
            .redact();
            let _ = DisplayTree::Branch(
                String::from("secret"),
                Box::new(DisplayTree::Leaf(String::from("secret"))),
            )
            .redacted_display()
            .to_string();
        }
    }

    pub fn exercise() {
        let _ = SelfNode {
            value: String::from("secret"),
            next: None,
        }
        .redact();
        let _ = SelfDisplayNode {
            value: String::from("secret"),
            next: None,
        }
            .redacted_display()
            .to_string();
        let _ = SelfDualNode {
            value: String::from("secret"),
            next: None,
        }
        .redact();
        tree::exercise();
    }
}

mod recursion_complements {
    use redactable::{
        Redactable, RedactableWithFormatter, RedactableWithMapper, Sensitive, SensitiveDisplay,
    };

    mod other {
        use redactable::Sensitive;

        #[derive(Sensitive)]
        pub struct Node<T> {
            pub value: T,
        }
    }

    #[derive(Sensitive)]
    struct Node<T> {
        child: crate::recursion_complements::other::Node<T>,
    }

    fn redact_unrelated<T>(value: Node<T>) -> Node<T>
    where
        crate::recursion_complements::other::Node<T>: RedactableWithMapper,
    {
        value.redact()
    }

    #[derive(Sensitive)]
    struct MutualA {
        next: Option<Box<MutualB>>,
    }

    #[derive(Sensitive)]
    struct MutualB {
        next: Option<Box<MutualA>>,
    }

    #[derive(SensitiveDisplay)]
    #[error("a {next:?}")]
    struct DisplayA {
        next: Option<Box<DisplayB>>,
    }

    #[derive(SensitiveDisplay)]
    #[error("b {next:?}")]
    struct DisplayB {
        next: Option<Box<DisplayA>>,
    }

    pub fn exercise() {
        let _ = redact_unrelated(Node {
            child: other::Node {
                value: String::from("secret"),
            },
        });
        let _ = MutualA { next: None }.redact();
        let _ = MutualB { next: None }.redact();
        let _ = DisplayA { next: None }.redacted_display().to_string();
        let _ = DisplayB { next: None }.redacted_display().to_string();
    }
}

mod explicit_recursion {
    use redactable::{
        Redactable, RedactableWithFormatter, Sensitive, SensitiveDisplay, SensitiveDual,
    };

    #[derive(Sensitive)]
    pub struct QualifiedNode<T> {
        value: T,
        #[redactable(recursive)]
        next: Option<Box<crate::explicit_recursion::QualifiedNode<T>>>,
    }

    #[derive(Sensitive)]
    pub enum QualifiedEnum<T> {
        Next(
            T,
            #[redactable(recursive)] Box<crate::explicit_recursion::QualifiedEnum<T>>,
        ),
        End(T),
    }

    type Alias<T> = AliasNode<T>;

    #[derive(Sensitive)]
    pub struct AliasNode<T> {
        value: T,
        #[redactable(recursive)]
        next: Option<Box<Alias<T>>>,
    }

    #[derive(Sensitive)]
    pub struct MutualA<T> {
        value: T,
        #[redactable(recursive)]
        next: Option<Box<MutualB<T>>>,
    }

    #[derive(Sensitive)]
    pub struct MutualB<T> {
        value: T,
        #[redactable(recursive)]
        next: Option<Box<MutualA<T>>>,
    }

    #[derive(SensitiveDisplay)]
    #[error("qualified {value:?} {next:?}")]
    pub struct QualifiedDisplayNode<T> {
        value: T,
        #[redactable(recursive)]
        next: Option<Box<crate::explicit_recursion::QualifiedDisplayNode<T>>>,
    }

    #[derive(SensitiveDisplay)]
    pub enum QualifiedDisplayEnum<T> {
        #[error("next {0:?} {1:?}")]
        Next(
            T,
            #[redactable(recursive)] Box<crate::explicit_recursion::QualifiedDisplayEnum<T>>,
        ),
        #[error("end {0:?}")]
        End(T),
    }

    type DisplayAlias<T> = AliasDisplayNode<T>;

    #[derive(SensitiveDisplay)]
    #[error("alias {value:?} {next:?}")]
    pub struct AliasDisplayNode<T> {
        value: T,
        #[redactable(recursive)]
        next: Option<Box<DisplayAlias<T>>>,
    }

    #[derive(SensitiveDisplay)]
    #[error("a {value:?} {next:?}")]
    pub struct DisplayMutualA<T> {
        value: T,
        #[redactable(recursive)]
        next: Option<Box<DisplayMutualB<T>>>,
    }

    #[derive(SensitiveDisplay)]
    #[error("b {value:?} {next:?}")]
    pub struct DisplayMutualB<T> {
        value: T,
        #[redactable(recursive)]
        next: Option<Box<DisplayMutualA<T>>>,
    }

    #[derive(SensitiveDual)]
    #[error("dual {value:?} {next:?}")]
    pub struct QualifiedDualNode<T> {
        value: T,
        #[redactable(recursive)]
        next: Option<Box<crate::explicit_recursion::QualifiedDualNode<T>>>,
    }

    pub fn exercise() {
        let _ = QualifiedNode {
            value: String::from("secret"),
            next: None,
        }
        .redact();
        let _ = QualifiedEnum::Next(
            String::from("secret"),
            Box::new(QualifiedEnum::End(String::from("secret"))),
        )
        .redact();
        let _ = AliasNode {
            value: String::from("secret"),
            next: None,
        }
        .redact();
        let _ = MutualA {
            value: String::from("secret"),
            next: None,
        }
        .redact();
        let _ = MutualB {
            value: String::from("secret"),
            next: None,
        }
        .redact();
        let _ = MutualA {
            value: String::from("public"),
            next: Some(Box::new(MutualB {
                value: String::from("public"),
                next: None,
            })),
        }
        .redact();
        let _ = QualifiedDisplayNode {
            value: String::from("secret"),
            next: None,
        }
        .redacted_display()
        .to_string();
        let _ = QualifiedDisplayEnum::Next(
            String::from("secret"),
            Box::new(QualifiedDisplayEnum::End(String::from("secret"))),
        )
        .redacted_display()
        .to_string();
        let _ = AliasDisplayNode {
            value: String::from("secret"),
            next: None,
        }
        .redacted_display()
        .to_string();
        let _ = DisplayMutualA {
            value: String::from("secret"),
            next: None,
        }
        .redacted_display()
        .to_string();
        let _ = DisplayMutualB {
            value: String::from("secret"),
            next: None,
        }
        .redacted_display()
        .to_string();
        let _ = QualifiedDualNode {
            value: String::from("secret"),
            next: None,
        }
        .redact();
    }
}

mod qualified {
    use redactable::{RedactableMapper, RedactableWithMapper};

    pub struct Node<T>(pub T);

    impl<T: RedactableWithMapper> RedactableWithMapper for Node<T> {
        fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
            Self(self.0.redact_with(mapper))
        }
    }
}

mod qualified_same_name {
    use redactable::{Redactable, RedactableMapper, RedactableWithMapper, Sensitive};

    pub mod other {
        use super::{RedactableMapper, RedactableWithMapper};

        pub struct Node<T>(pub T);

        impl<T: RedactableWithMapper> RedactableWithMapper for Node<T> {
            fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
                Self(self.0.redact_with(mapper))
            }
        }
    }

    #[derive(Sensitive)]
    struct Node<T> {
        child: other::Node<T>,
    }

    pub fn exercise() {
        let _ = Node {
            child: other::Node(String::from("secret")),
        }
        .redact();
    }
}

#[derive(SensitiveDisplay)]
#[error("{value:?}")]
struct GenericGenerated<T>
where
    T: redactable::__private::PolicyApplicableRefForGeneratedFormatting,
    redactable::SecretPolicyKind:
        redactable::__private::PolicyKindDebugFormatting<redactable::Secret, T>,
{
    #[sensitive(Secret)]
    value: T,
}

#[derive(Sensitive)]
struct QualifiedNode<T> {
    child: qualified::Node<T>,
}

type QualifiedAlias<T> = qualified::Node<T>;

#[derive(Sensitive)]
struct AliasQualifiedNode<T> {
    child: QualifiedAlias<T>,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
struct FlagKey;

impl fmt::Debug for FlagKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if formatter.alternate() {
            ALTERNATE_KEY_DEBUGS.fetch_add(1, Ordering::SeqCst);
            formatter.write_str("AlternateKey")
        } else {
            COMPACT_KEY_DEBUGS.fetch_add(1, Ordering::SeqCst);
            formatter.write_str("CompactKey")
        }
    }
}

#[derive(SensitiveDisplay)]
#[error("{records:?}")]
struct CompactMap {
    #[sensitive(Secret)]
    records: BTreeMap<FlagKey, String>,
}

#[derive(SensitiveDisplay)]
#[error("{records:#?}")]
struct AlternateMap {
    #[sensitive(Secret)]
    records: BTreeMap<FlagKey, String>,
}

#[derive(SensitiveDisplay)]
#[error("{records:?}")]
struct NestedCompactBTreeMap {
    #[sensitive(Secret)]
    records: Option<Vec<BTreeMap<FlagKey, String>>>,
}

#[derive(SensitiveDisplay)]
#[error("{records:#?}")]
struct NestedAlternateBTreeMap {
    #[sensitive(Secret)]
    records: Option<Vec<BTreeMap<FlagKey, String>>>,
}

#[derive(SensitiveDisplay)]
#[error("{records:?}")]
struct BoxedCompactBTreeMap {
    #[sensitive(Secret)]
    records: Box<BTreeMap<FlagKey, String>>,
}

#[derive(SensitiveDisplay)]
#[error("{records:#?}")]
struct BoxedAlternateBTreeMap {
    #[sensitive(Secret)]
    records: Box<BTreeMap<FlagKey, String>>,
}

#[derive(SensitiveDisplay)]
#[error("{records:?}")]
struct NestedCompactHashMap {
    #[sensitive(Secret)]
    records: Option<Vec<HashMap<FlagKey, String, NonCloneBuildHasher>>>,
}

#[derive(SensitiveDisplay)]
#[error("{records:#?}")]
struct NestedAlternateHashMap {
    #[sensitive(Secret)]
    records: Option<Vec<HashMap<FlagKey, String, NonCloneBuildHasher>>>,
}

#[derive(SensitiveDisplay)]
#[error("{records:?}")]
struct NestedBorrowedBTreeMap {
    #[sensitive(Secret)]
    records: Option<Vec<BTreeMap<FlagKey, RefCell<String>>>>,
}

// A `pub` type deriving `Sensitive` must not leak the visibility of its field
// types. The removed owned-capability hierarchy emitted the derived type's
// field types into a public associated type, so this shape failed to compile
// with `error[E0446]: private type `PrivateDetail` in public interface`. This
// fixture is a real downstream consumer, so the public/private boundary here is
// the one a library author actually hits.
mod public_api_boundary {
    use redactable::{
        IntoRedactedOutputExt, Redactable, RedactableMapper, RedactableWithMapper, RedactedOutput,
        Secret, Sensitive,
    };
    use serde::Serialize;

    #[derive(Clone, Debug, Serialize)]
    struct PrivateDetail {
        note: String,
    }

    impl RedactableWithMapper for PrivateDetail {
        fn redact_with<M: RedactableMapper>(self, _mapper: &M) -> Self {
            self
        }
    }

    /// Public named struct holding a private field type.
    #[derive(Clone, Sensitive, Serialize)]
    pub struct PublicEvent {
        #[sensitive(Secret)]
        pub token: String,
        detail: PrivateDetail,
    }

    /// Public tuple struct holding a private field type.
    #[derive(Clone, Sensitive)]
    pub struct PublicTuple(#[sensitive(Secret)] pub String, PrivateDetail);

    /// Public generic struct holding a private field type.
    #[derive(Clone, Sensitive)]
    pub struct PublicGeneric<T> {
        pub label: T,
        detail: PrivateDetail,
    }

    fn detail() -> PrivateDetail {
        PrivateDetail {
            note: "note-canary".to_owned(),
        }
    }

    pub fn exercise() {
        let event = PublicEvent {
            token: "token-canary".to_owned(),
            detail: detail(),
        };
        let redacted = event.clone().redact();
        assert_eq!(redacted.token, "[REDACTED]");
        // The unannotated private field is walked, not redacted.
        assert_eq!(redacted.detail.note, "note-canary");

        // The same shape through the consuming adapter.
        let output = match event.into_redacted_output() {
            RedactedOutput::Text(output) => output,
            other => panic!("structural output should be text, got {other:?}"),
        };
        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains("token-canary"));

        let tuple = PublicTuple("token-canary".to_owned(), detail()).redact();
        assert_eq!(tuple.0, "[REDACTED]");

        let generic = PublicGeneric {
            label: 7_u8,
            detail: detail(),
        }
        .redact();
        assert_eq!(generic.label, 7);
    }
}

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
        GenericPolicyIpEnum::<IpAddress>::Renamed(
            Ipv4Addr::new(192, 168, 10, 99),
            PhantomData,
        )
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

    let recursive_slog = match redactable::slog::SlogRedactedExt::slog_redacted_json(
        secret_recursive_node(),
    )
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
    assert!(format!("{}", OrderedSetOfMaps { records: ordered }.redacted_display())
        .contains("[REDACTED]"));

    let hashed = HashSet::from([BTreeMap::from([(
        String::from("key"),
        String::from("secret"),
    )])]);
    assert!(format!("{}", HashedSetOfMaps { records: hashed }.redacted_display())
        .contains("[REDACTED]"));

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
    assert_eq!(
        generated.redacted_display().to_string(),
        "<borrowed>"
    );
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
        records: Some(vec![BTreeMap::from([(
            FlagKey,
            String::from("secret"),
        )])]),
    };
    let compact = nested_compact_btree.redacted_display().to_string();
    assert!(compact.contains("CompactKey"));
    assert!(!compact.contains("AlternateKey"));
    assert_eq!(COMPACT_KEY_DEBUGS.load(Ordering::SeqCst), 1);
    assert_eq!(ALTERNATE_KEY_DEBUGS.load(Ordering::SeqCst), 0);

    COMPACT_KEY_DEBUGS.store(0, Ordering::SeqCst);
    ALTERNATE_KEY_DEBUGS.store(0, Ordering::SeqCst);
    let nested_alternate_btree = NestedAlternateBTreeMap {
        records: Some(vec![BTreeMap::from([(
            FlagKey,
            String::from("secret"),
        )])]),
    };
    let alternate = nested_alternate_btree.redacted_display().to_string();
    assert!(alternate.contains("AlternateKey"));
    assert!(!alternate.contains("CompactKey"));
    assert_eq!(COMPACT_KEY_DEBUGS.load(Ordering::SeqCst), 0);
    assert_eq!(ALTERNATE_KEY_DEBUGS.load(Ordering::SeqCst), 1);

    COMPACT_KEY_DEBUGS.store(0, Ordering::SeqCst);
    ALTERNATE_KEY_DEBUGS.store(0, Ordering::SeqCst);
    let boxed_compact = BoxedCompactBTreeMap {
        records: Box::new(BTreeMap::from([(
            FlagKey,
            String::from("secret"),
        )])),
    };
    let compact = boxed_compact.redacted_display().to_string();
    assert!(compact.contains("CompactKey"));
    assert!(!compact.contains("AlternateKey"));
    assert_eq!(COMPACT_KEY_DEBUGS.load(Ordering::SeqCst), 1);
    assert_eq!(ALTERNATE_KEY_DEBUGS.load(Ordering::SeqCst), 0);

    COMPACT_KEY_DEBUGS.store(0, Ordering::SeqCst);
    ALTERNATE_KEY_DEBUGS.store(0, Ordering::SeqCst);
    let boxed_alternate = BoxedAlternateBTreeMap {
        records: Box::new(BTreeMap::from([(
            FlagKey,
            String::from("secret"),
        )])),
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
