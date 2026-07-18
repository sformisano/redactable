// A `pub` type deriving `Sensitive` must not leak the visibility of its field
// types. The removed owned-capability hierarchy emitted
// `type Driver = __RedactableOwnedCapability<Self, #field_types..>` as a public
// associated type on a public trait impl, so a private field type landed in a
// public interface and rustc rejected the type outright with
// `error[E0446]: private type `PrivateDetail` in public interface`.
//
// The `pub` types below are reachable through `pub mod api`, so their effective
// visibility exceeds the private field type they hold. Keep `PrivateDetail`
// private and keep its containers `pub`: that gap is the whole assertion.
//
// Only struct shapes appear here. A `pub enum` cannot host this assertion
// cleanly: enum variant fields are implicitly as public as the enum itself, so
// a private variant field type trips the ordinary `private_interfaces` lint on
// the enum declaration regardless of what the derive generates. Structs isolate
// the derive-generated leak with no unrelated diagnostic.

pub mod api {
    use redactable::{Redactable, RedactableMapper, RedactableWithMapper, Secret, Sensitive};

    #[derive(Clone, Debug)]
    struct PrivateDetail {
        note: String,
    }

    impl RedactableWithMapper for PrivateDetail {
        fn redact_with<M: RedactableMapper>(self, _mapper: &M) -> Self {
            self
        }
    }

    /// Public named struct holding a private field type.
    #[derive(Clone, Sensitive)]
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
        }
        .redact();
        assert_eq!(event.token, "[REDACTED]");
        // Unannotated private field is walked, not redacted.
        assert_eq!(event.detail.note, "note-canary");

        let tuple = PublicTuple("token-canary".to_owned(), detail()).redact();
        assert_eq!(tuple.0, "[REDACTED]");
        assert_eq!(tuple.1.note, "note-canary");

        let generic = PublicGeneric {
            label: 7_u8,
            detail: detail(),
        }
        .redact();
        assert_eq!(generic.label, 7);
        assert_eq!(generic.detail.note, "note-canary");
    }
}

fn main() {
    api::exercise();
}
