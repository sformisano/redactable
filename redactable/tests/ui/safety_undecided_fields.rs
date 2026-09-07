use redactable::{Redactable, Sensitive, SensitiveDisplay, SensitiveDual};
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, HashMap, VecDeque},
    rc::Rc,
    sync::{Arc, Mutex, RwLock},
};
type RawAlias = String;
#[derive(Clone, serde::Serialize, Sensitive)]
struct Structural0 {
    field: RawAlias,
}
#[derive(Clone, serde::Serialize, Sensitive)]
struct Structural1 {
    field: Option<String>,
}
#[derive(Clone, serde::Serialize, Sensitive)]
struct Structural2 {
    field: Vec<String>,
}
#[derive(Clone, serde::Serialize, Sensitive)]
struct Structural3 {
    field: VecDeque<String>,
}
#[derive(Clone, serde::Serialize, Sensitive)]
struct Structural4 {
    field: [String; 2],
}
#[derive(Clone, serde::Serialize, Sensitive)]
struct Structural5 {
    field: Box<String>,
}
#[derive(Clone, serde::Serialize, Sensitive)]
struct Structural6 {
    // `serde` implements `Serialize` for `Rc`/`Arc` only under its `rc`
    // feature; skipping keeps the mandatory bound satisfiable so the missing
    // redaction declaration stays the only diagnostic.
    #[serde(skip)]
    field: Rc<String>,
}
#[derive(Clone, serde::Serialize, Sensitive)]
struct Structural7 {
    #[serde(skip)]
    field: Arc<String>,
}
#[derive(Clone, serde::Serialize, Sensitive)]
struct Structural8 {
    field: RefCell<String>,
}
#[derive(Clone, serde::Serialize, Sensitive)]
struct Structural9 {
    field: Cell<u8>,
}
#[derive(Clone, serde::Serialize, Sensitive)]
struct Structural10 {
    field: Mutex<String>,
}
#[derive(Clone, serde::Serialize, Sensitive)]
struct Structural11 {
    field: RwLock<String>,
}
#[derive(Clone, serde::Serialize, Sensitive)]
struct Structural12 {
    field: Result<String, String>,
}
#[derive(Clone, serde::Serialize, Sensitive)]
struct Structural13 {
    field: (String, String),
}
#[derive(Clone, serde::Serialize, Sensitive)]
struct Structural14 {
    field: HashMap<String, String>,
}
#[derive(Clone, serde::Serialize, Sensitive)]
struct Structural15 {
    field: BTreeMap<String, String>,
}
#[derive(SensitiveDisplay)]
#[error("{field} ")]
struct Formatting0 {
    field: RawAlias,
}
#[derive(SensitiveDisplay)]
#[error("{field} ")]
struct Formatting1 {
    field: Option<String>,
}
#[derive(SensitiveDisplay)]
#[error("{field} ")]
struct Formatting2 {
    field: Vec<String>,
}
#[derive(SensitiveDisplay)]
#[error("{field} ")]
struct Formatting3 {
    field: VecDeque<String>,
}
#[derive(SensitiveDisplay)]
#[error("{field} ")]
struct Formatting4 {
    field: [String; 2],
}
#[derive(SensitiveDisplay)]
#[error("{field} ")]
struct Formatting5 {
    field: Box<String>,
}
#[derive(SensitiveDisplay)]
#[error("{field} ")]
struct Formatting6 {
    field: Rc<String>,
}
#[derive(SensitiveDisplay)]
#[error("{field} ")]
struct Formatting7 {
    field: Arc<String>,
}
#[derive(SensitiveDisplay)]
#[error("{field} ")]
struct Formatting8 {
    field: RefCell<String>,
}
#[derive(SensitiveDisplay)]
#[error("{field} ")]
struct Formatting9 {
    field: Cell<u8>,
}
#[derive(SensitiveDisplay)]
#[error("{field} ")]
struct Formatting10 {
    field: Mutex<String>,
}
#[derive(SensitiveDisplay)]
#[error("{field} ")]
struct Formatting11 {
    field: RwLock<String>,
}
#[derive(SensitiveDisplay)]
#[error("{field} ")]
struct Formatting12 {
    field: Result<String, String>,
}
#[derive(SensitiveDisplay)]
#[error("{field} ")]
struct Formatting13 {
    field: (String, String),
}
#[derive(SensitiveDisplay)]
#[error("{field} ")]
struct Formatting14 {
    field: HashMap<String, String>,
}
#[derive(SensitiveDisplay)]
#[error("{field} ")]
struct Formatting15 {
    field: BTreeMap<String, String>,
}
#[derive(Clone, serde::Serialize, SensitiveDual)]
#[error("summary")]
struct DualOmission {
    undecided: String,
}
#[derive(Clone, serde::Serialize, Sensitive)]
struct Generic<T>(T);
fn main() {
    let _ = Generic(String::new()).redact();
}
