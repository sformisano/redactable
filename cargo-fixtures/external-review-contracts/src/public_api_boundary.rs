// A `pub` type deriving `Sensitive` must not leak the visibility of its field
// types. The removed owned-capability hierarchy emitted the derived type's
// field types into a public associated type, so this shape failed to compile
// with `error[E0446]: private type `PrivateDetail` in public interface`. This
// fixture is a real downstream consumer, so the public/private boundary here is
// the one a library author actually hits.
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
