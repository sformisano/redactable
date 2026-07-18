use redactable::{
    Redactable, RedactableWithFormatter, RedactableWithMapper, Sensitive, SensitiveDisplay,
};

mod other {
    use redactable::Sensitive;

    #[derive(Sensitive)]
    pub struct Node<T> {
        pub value: T,
    }
}

#[derive(Sensitive)]
struct Node<T> {
    child: crate::recursion_complements::other::Node<T>,
}

fn redact_unrelated<T>(value: Node<T>) -> Node<T>
where
    crate::recursion_complements::other::Node<T>: RedactableWithMapper,
{
    value.redact()
}

#[derive(Sensitive)]
struct MutualA {
    next: Option<Box<MutualB>>,
}

#[derive(Sensitive)]
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
    let _ = redact_unrelated(Node {
        child: other::Node {
            value: String::from("secret"),
        },
    });
    let _ = MutualA { next: None }.redact();
    let _ = MutualB { next: None }.redact();
    let _ = DisplayA { next: None }.redacted_display().to_string();
    let _ = DisplayB { next: None }.redacted_display().to_string();
}
