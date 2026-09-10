//! `Clone + Serialize` (and `Serialize` alone for `NotSensitive`) are the only
//! bounds the derives add, and generic parameters may supply them.

use redactable::{
    NotSensitive, RedactedValue, Secret, Sensitive, SensitiveDisplay, SensitiveDual, ToRedacted,
};
use serde::{Serialize, Serializer};

#[derive(Clone, Serialize, Sensitive)]
struct Structural<T> {
    item: T,
    #[not_sensitive]
    approved: bool,
}

#[derive(Clone, Serialize, SensitiveDual)]
#[error("{name}")]
struct Person {
    #[sensitive(Secret)]
    name: String,
}

#[derive(SensitiveDisplay)]
#[error("no bounds needed")]
struct DisplayOnly;

#[derive(Serialize, NotSensitive)]
struct Public {
    approved: bool,
}

struct Manual(Person);

impl ToRedacted for Manual {
    fn to_redacted(&self) -> RedactedValue {
        self.0.to_redacted()
    }
}

#[derive(Clone, Sensitive)]
struct Fallible;

impl Serialize for Fallible {
    fn serialize<S: Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as SerError;

        Err(SerError::custom("failure"))
    }
}

fn sink<T: ToRedacted>(value: &T) -> RedactedValue {
    value.to_redacted()
}

fn main() {
    let person = Person { name: "Ada".into() };
    let selected = sink(&Structural {
        item: person.clone(),
        approved: true,
    });
    assert_eq!(
        selected.json(),
        serde_json::json!({"item":{"name":"[REDACTED]"},"approved":true})
    );
    assert_eq!(sink(&Manual(person.clone())), sink(&person));
    assert_eq!(sink(&person).text(), "[REDACTED]");
    assert_eq!(
        serde_json::to_value(&person).unwrap(),
        serde_json::json!({"name":"Ada"})
    );
    assert_eq!(sink(&DisplayOnly).text(), "no bounds needed");
    assert_eq!(
        sink(&Public { approved: true }).json(),
        serde_json::json!({"approved": true})
    );
    assert_eq!(
        Fallible.to_redacted().json(),
        serde_json::Value::String("[REDACTED]".into())
    );
}
