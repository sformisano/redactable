// Qualified type paths intentionally exercise derive name resolution.
use redactable::{Redactable, RedactableWithFormatter, Sensitive, SensitiveDisplay};
use redactable::{Secret, SensitiveValue};

mod other {
    use redactable::Sensitive;

    #[derive(Clone, serde::Serialize, Sensitive)]
    pub struct Node<T> {
        pub value: T,
    }
}

#[derive(Clone, serde::Serialize, Sensitive)]
struct Node<T> {
    child: crate::recursion_complements::other::Node<T>,
}

fn redact_unrelated<T>(value: Node<T>) -> Node<T>
where
    crate::recursion_complements::other::Node<T>: Redactable,
{
    value.redact()
}

#[derive(Clone, serde::Serialize, Sensitive)]
struct MutualA {
    next: Option<Box<MutualB>>,
}

#[derive(Clone, serde::Serialize, Sensitive)]
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
    use self::other::Node as OtherNode;

    let _ = redact_unrelated(Node {
        child: OtherNode {
            value: SensitiveValue::<String, Secret>::from(String::from("secret")),
        },
    });
    let _ = MutualA { next: None }.redact();
    let _ = MutualB { next: None }.redact();
    let _ = DisplayA { next: None }.redacted_display().to_string();
    let _ = DisplayB { next: None }.redacted_display().to_string();
}
