use std::{
    cell::RefCell,
    collections::BTreeMap,
    marker::PhantomData,
    rc::Rc,
    sync::Arc,
};

use redactable::{
    IntoRedactedJsonExt, IntoRedactedOutputExt, IpAddress, RedactableWithFormatter,
    RedactedJsonExt, RedactedOutputExt, RedactionPolicy, Secret, Sensitive, SensitiveDisplay,
    ToRedactedOutput,
};
use redactable::tracing::{
    IntoTracingRedactedDebugExt, TracingRedactedDebugExt, TracingRedactedExt,
};
use serde::Serialize;

type CellAlias<T> = RefCell<T>;
type NestedCellAlias<T> = Option<CellAlias<T>>;
type ArcCellAlias<T> = Arc<CellAlias<T>>;
type RcCellAlias<T> = Rc<CellAlias<T>>;

#[derive(SensitiveDisplay)]
#[error("{value}")]
struct GenericAliasDisplay<P: RedactionPolicy, T> {
    #[sensitive(P)]
    value: NestedCellAlias<T>,
    marker: PhantomData<P>,
}

#[derive(SensitiveDisplay)]
#[error("{value} | {value:?}")]
struct ArcAliasDisplay<P: RedactionPolicy, T> {
    #[sensitive(P)]
    value: ArcCellAlias<T>,
    marker: PhantomData<P>,
}

#[derive(SensitiveDisplay)]
#[error("{value} | {value:?}")]
struct RcAliasDisplay<P: RedactionPolicy, T> {
    #[sensitive(P)]
    value: RcCellAlias<T>,
    marker: PhantomData<P>,
}

fn assert_borrow_conflict<P>()
where
    P: RedactionPolicy,
    GenericAliasDisplay<P, String>: RedactableWithFormatter,
{
    let display = GenericAliasDisplay::<P, String> {
        value: Some(RefCell::new("panic-abort-canary".to_owned())),
        marker: PhantomData,
    };
    let _borrow = display
        .value
        .as_ref()
        .expect("fixture value is present")
        .borrow_mut();

    assert_eq!(display.redacted_display().to_string(), "<borrowed>");
}

fn assert_pointer_borrow_states<P>()
where
    P: RedactionPolicy,
    ArcAliasDisplay<P, String>: RedactableWithFormatter,
    RcAliasDisplay<P, String>: RedactableWithFormatter,
{
    let arc = ArcAliasDisplay::<P, String> {
        value: Arc::new(RefCell::new("panic-abort-canary".to_owned())),
        marker: PhantomData,
    };
    let unborrowed = arc.redacted_display().to_string();
    assert!(!unborrowed.contains("panic-abort-canary"));
    let shared = arc.value.borrow();
    let shared_output = arc.redacted_display().to_string();
    assert!(!shared_output.contains("panic-abort-canary"));
    drop(shared);
    let mutable = arc.value.borrow_mut();
    assert_eq!(arc.redacted_display().to_string(), "<borrowed> | <borrowed>");
    drop(mutable);

    let rc = RcAliasDisplay::<P, String> {
        value: Rc::new(RefCell::new("panic-abort-canary".to_owned())),
        marker: PhantomData,
    };
    let unborrowed = rc.redacted_display().to_string();
    assert!(!unborrowed.contains("panic-abort-canary"));
    let shared = rc.value.borrow();
    let shared_output = rc.redacted_display().to_string();
    assert!(!shared_output.contains("panic-abort-canary"));
    drop(shared);
    let mutable = rc.value.borrow_mut();
    assert_eq!(rc.redacted_display().to_string(), "<borrowed> | <borrowed>");
    drop(mutable);
}

#[derive(SensitiveDisplay)]
#[error("{values} | {values:?}")]
struct BorrowedKeyDisplay {
    #[sensitive(Secret)]
    values: BTreeMap<RefCell<String>, String>,
}

#[derive(SensitiveDisplay)]
#[error("{values}")]
struct NestedBorrowedKeyDisplay {
    #[sensitive(Secret)]
    values: Option<BTreeMap<RefCell<String>, String>>,
}

#[derive(SensitiveDisplay)]
#[error("{values}")]
struct GenericBorrowedKeyDisplay<T> {
    #[sensitive(Secret)]
    values: T,
}

#[derive(SensitiveDisplay)]
#[error("{values}")]
struct BoxedBorrowedKeyDisplay {
    #[sensitive(Secret)]
    values: BTreeMap<Box<RefCell<String>>, String>,
}

fn assert_borrowed_map_key() {
    let value = BorrowedKeyDisplay {
        values: BTreeMap::from([(
            RefCell::new("panic-abort-canary".to_owned()),
            "panic-abort-canary".to_owned(),
        )]),
    };
    let borrow = value.values.keys().next().unwrap().borrow_mut();
    let output = value.redacted_display().to_string();
    assert!(output.contains("<borrowed>"));
    assert!(!output.contains("panic-abort-canary"));
    drop(borrow);

    let nested = NestedBorrowedKeyDisplay {
        values: Some(BTreeMap::from([(
            RefCell::new("public-key".to_owned()),
            "panic-abort-canary".to_owned(),
        )])),
    };
    let borrow = nested.values.as_ref().unwrap().keys().next().unwrap().borrow_mut();
    let output = nested.redacted_display().to_string();
    assert!(output.contains("<borrowed>"));
    assert!(!output.contains("panic-abort-canary"));
    drop(borrow);

    let generic = GenericBorrowedKeyDisplay {
        values: BTreeMap::from([(
            RefCell::new("public-key".to_owned()),
            "panic-abort-canary".to_owned(),
        )]),
    };
    let borrow = generic.values.keys().next().unwrap().borrow_mut();
    let output = generic.redacted_display().to_string();
    assert!(output.contains("<borrowed>"));
    assert!(!output.contains("panic-abort-canary"));
    drop(borrow);

    let boxed = BoxedBorrowedKeyDisplay {
        values: BTreeMap::from([(
            Box::new(RefCell::new("public-key".to_owned())),
            "panic-abort-canary".to_owned(),
        )]),
    };
    let borrow = boxed.values.keys().next().unwrap().borrow_mut();
    let output = boxed.redacted_display().to_string();
    assert!(output.contains("<borrowed>"));
    assert!(!output.contains("panic-abort-canary"));
    drop(borrow);
}

#[derive(Clone, Sensitive, Serialize)]
struct BorrowedAdapterEvent {
    #[sensitive(Secret)]
    secret: RefCell<String>,
}

fn borrowed_adapter_event() -> BorrowedAdapterEvent {
    BorrowedAdapterEvent {
        secret: RefCell::new("borrowed-adapter-panic-abort-canary".to_owned()),
    }
}

fn run_borrowed_adapter_mode(mode: &str) {
    let value = borrowed_adapter_event();
    let _borrow = value.secret.borrow_mut();
    match mode {
        "borrowed-output" => {
            let _ = value.redacted_output().to_redacted_output();
        }
        "borrowed-json" => {
            let _ = value.redacted_json().to_redacted_output();
        }
        "borrowed-tracing-debug" => {
            let _ = value.tracing_redacted_debug();
        }
        "borrowed-tracing-display" => {
            let _ = value.redacted_output().tracing_redacted();
        }
        _ => panic!("unknown borrowed adapter mode"),
    }
}

fn run_consuming_adapter_mode(mode: &str) {
    let value = borrowed_adapter_event();
    let borrow = value.secret.borrow_mut();
    std::mem::forget(borrow);
    match mode {
        "consuming-output" => {
            let _ = value.into_redacted_output();
        }
        "consuming-json" => {
            let _ = value.into_redacted_json().to_redacted_output();
        }
        "consuming-tracing-debug" => {
            let _ = value.into_tracing_redacted_debug();
        }
        _ => panic!("unknown consuming adapter mode"),
    }
}

fn main() {
    if let Some(mode) = std::env::args().nth(1) {
        if mode.starts_with("consuming-") {
            run_consuming_adapter_mode(&mode);
        } else {
            run_borrowed_adapter_mode(&mode);
        }
        return;
    }
    assert_borrow_conflict::<Secret>();
    assert_borrow_conflict::<IpAddress>();
    assert_pointer_borrow_states::<Secret>();
    assert_pointer_borrow_states::<IpAddress>();
    assert_borrowed_map_key();
}
