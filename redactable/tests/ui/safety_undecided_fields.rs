use redactable::{Redactable, Sensitive, SensitiveDisplay, SensitiveDual};
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, HashMap, VecDeque},
    rc::Rc,
    sync::{Arc, Mutex, RwLock},
};
type RawAlias = String;
#[derive(Sensitive)]
struct Structural0 {
    field: RawAlias,
}
#[derive(Sensitive)]
struct Structural1 {
    field: Option<String>,
}
#[derive(Sensitive)]
struct Structural2 {
    field: Vec<String>,
}
#[derive(Sensitive)]
struct Structural3 {
    field: VecDeque<String>,
}
#[derive(Sensitive)]
struct Structural4 {
    field: [String; 2],
}
#[derive(Sensitive)]
struct Structural5 {
    field: Box<String>,
}
#[derive(Sensitive)]
struct Structural6 {
    field: Rc<String>,
}
#[derive(Sensitive)]
struct Structural7 {
    field: Arc<String>,
}
#[derive(Sensitive)]
struct Structural8 {
    field: RefCell<String>,
}
#[derive(Sensitive)]
struct Structural9 {
    field: Cell<u8>,
}
#[derive(Sensitive)]
struct Structural10 {
    field: Mutex<String>,
}
#[derive(Sensitive)]
struct Structural11 {
    field: RwLock<String>,
}
#[derive(Sensitive)]
struct Structural12 {
    field: Result<String, String>,
}
#[derive(Sensitive)]
struct Structural13 {
    field: (String, String),
}
#[derive(Sensitive)]
struct Structural14 {
    field: HashMap<String, String>,
}
#[derive(Sensitive)]
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
#[derive(SensitiveDual)]
#[error("summary")]
struct DualOmission {
    undecided: String,
}
#[derive(Sensitive)]
struct Generic<T>(T);
fn main() {
    let _ = Generic(String::new()).redact();
}
