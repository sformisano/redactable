use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    hash::{BuildHasher, Hasher},
};

use redactable::{Secret, SensitiveDisplay};

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct NonCloneKey(pub &'static str);

#[derive(Default)]
pub struct NonCloneHasher;

impl Hasher for NonCloneHasher {
    fn finish(&self) -> u64 {
        0
    }

    fn write(&mut self, _bytes: &[u8]) {}
}

pub struct NonCloneBuildHasher;

impl BuildHasher for NonCloneBuildHasher {
    type Hasher = NonCloneHasher;

    fn build_hasher(&self) -> Self::Hasher {
        NonCloneHasher
    }
}

#[derive(SensitiveDisplay)]
#[error("{records:#?}")]
pub struct NonCloneMap {
    #[sensitive(Secret)]
    pub records: HashMap<NonCloneKey, String, NonCloneBuildHasher>,
}

#[derive(SensitiveDisplay)]
#[error("{records:?}")]
pub struct OrderedSetOfMaps {
    #[sensitive(Secret)]
    pub records: BTreeSet<BTreeMap<String, String>>,
}

#[derive(SensitiveDisplay)]
#[error("{records:?}")]
pub struct HashedSetOfMaps {
    #[sensitive(Secret)]
    pub records: HashSet<BTreeMap<String, String>>,
}

pub type Text<'a> = &'a str;

#[derive(SensitiveDisplay)]
#[error("{text}")]
pub struct AliasedText<'a> {
    #[sensitive(Secret)]
    pub text: Text<'a>,
}
