use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    fmt,
    sync::atomic::Ordering,
};

use redactable::{Secret, SensitiveDisplay};

use crate::{ALTERNATE_KEY_DEBUGS, COMPACT_KEY_DEBUGS, non_clone::NonCloneBuildHasher};

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlagKey;

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
pub struct CompactMap {
    #[sensitive(Secret)]
    pub records: BTreeMap<FlagKey, String>,
}

#[derive(SensitiveDisplay)]
#[error("{records:#?}")]
pub struct AlternateMap {
    #[sensitive(Secret)]
    pub records: BTreeMap<FlagKey, String>,
}

#[derive(SensitiveDisplay)]
#[error("{records:?}")]
pub struct NestedCompactBTreeMap {
    #[sensitive(Secret)]
    pub records: Option<Vec<BTreeMap<FlagKey, String>>>,
}

#[derive(SensitiveDisplay)]
#[error("{records:#?}")]
pub struct NestedAlternateBTreeMap {
    #[sensitive(Secret)]
    pub records: Option<Vec<BTreeMap<FlagKey, String>>>,
}

#[derive(SensitiveDisplay)]
#[error("{records:?}")]
pub struct BoxedCompactBTreeMap {
    #[sensitive(Secret)]
    pub records: Box<BTreeMap<FlagKey, String>>,
}

#[derive(SensitiveDisplay)]
#[error("{records:#?}")]
pub struct BoxedAlternateBTreeMap {
    #[sensitive(Secret)]
    pub records: Box<BTreeMap<FlagKey, String>>,
}

#[derive(SensitiveDisplay)]
#[error("{records:?}")]
pub struct NestedCompactHashMap {
    #[sensitive(Secret)]
    pub records: Option<Vec<HashMap<FlagKey, String, NonCloneBuildHasher>>>,
}

#[derive(SensitiveDisplay)]
#[error("{records:#?}")]
pub struct NestedAlternateHashMap {
    #[sensitive(Secret)]
    pub records: Option<Vec<HashMap<FlagKey, String, NonCloneBuildHasher>>>,
}

#[derive(SensitiveDisplay)]
#[error("{records:?}")]
pub struct NestedBorrowedBTreeMap {
    #[sensitive(Secret)]
    pub records: Option<Vec<BTreeMap<FlagKey, RefCell<String>>>>,
}
