use redactable::{
    IntoRedactedJsonExt, NotSensitiveJsonExt, RedactableWithFormatter, RedactedJsonExt,
    RedactedOutput, RedactedOutputView, Secret, Sensitive, SensitiveDual, ToRedactedOutput,
};
use serde::{Serialize, Serializer};
#[derive(Clone, Serialize, Sensitive)]
#[redactable(output = json)]
struct Output<T> {
    item: T,
    #[not_sensitive]
    approved: bool,
}
#[derive(Clone, Serialize, SensitiveDual)]
#[redactable(output = json)]
#[error("{name}")]
struct Person {
    #[sensitive(Secret)]
    name: String,
}
struct Manual(Person);
impl ToRedactedOutput for Manual {
    fn to_redacted_output(&self) -> RedactedOutput {
        self.0.redacted_json().to_redacted_output()
    }
}
#[derive(Clone, Sensitive)]
#[redactable(output = json)]
struct Fallible;
impl Serialize for Fallible {
    fn serialize<S: Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as SerError;

        Err(SerError::custom("failure"))
    }
}
#[derive(Serialize, Sensitive)]
struct Consuming {
    #[sensitive(Secret)]
    secret: String,
}
fn sink<T: ToRedactedOutput>(value: &T) -> RedactedOutput {
    value.to_redacted_output()
}
fn main() {
    let person = Person { name: "Ada".into() };
    assert_eq!(person.redacted_display().to_string(), "[REDACTED]");
    let selected = sink(&Output {
        item: person.clone(),
        approved: true,
    });
    match selected.view() {
        RedactedOutputView::Json(value) => assert_eq!(
            value,
            &serde_json::json!({"item":{"name":"[REDACTED]"},"approved":true})
        ),
        _ => panic!("JSON required"),
    }
    assert_eq!(sink(&Manual(person.clone())), sink(&person));
    assert_eq!(
        serde_json::to_value(&person).unwrap(),
        serde_json::json!({"name":"Ada"})
    );
    let _ = sink(&"foreign public".not_sensitive_json());
    let _ = Fallible.to_redacted_output();
    let _ = Consuming {
        secret: "secret".into(),
    }
    .into_redacted_json();
}
