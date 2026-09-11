// Qualified paths intentionally test exact owner recognition.
use redactable::{Redactable, Secret, Sensitive, SensitiveValue};

mod qualified {
    use redactable::{Redactable, Sensitive};
    pub mod other {
        use redactable::{Redactable, Sensitive};
        #[derive(Sensitive)]
        pub struct Node<T: Redactable> { pub value: T }
    }
    #[derive(Sensitive)]
    pub struct Node<T: Redactable> {
        pub child: self::other::Node<T>,
        pub next: Option<Box<self::Node<T>>>,
    }
}
mod ordinary {
    use redactable::{Redactable, Sensitive};
    pub mod other {
        use redactable::{Redactable, Sensitive};
        #[derive(Sensitive)]
        pub struct Node<T: Redactable> { pub value: T }
    }
    #[derive(Sensitive)]
    pub struct Node<T: Redactable> {
        pub child: other::Node<T>,
        pub next: Option<Box<Node<T>>>,
    }
}

type Alias<T> = Recursive<T>;
#[derive(Sensitive)]
struct Recursive<T: Redactable> {
    value: T,
    #[redactable(recursive)]
    next: Option<Box<Alias<T>>>,
}
#[derive(Sensitive)]
struct MutualA<T: Redactable> {
    value: T,
    #[redactable(recursive)]
    next: Option<Box<MutualB<T>>>,
}
#[derive(Sensitive)]
struct MutualB<T: Redactable> {
    value: T,
    #[redactable(recursive)]
    next: Option<Box<MutualA<T>>>,
}

fn main() {
    let qualified = qualified::Node {
        child: qualified::other::Node { value: SensitiveValue::<String, Secret>::from("canary".to_owned()) },
        next: None,
    }.redact();
    let ordinary = ordinary::Node {
        child: ordinary::other::Node { value: SensitiveValue::<String, Secret>::from("canary".to_owned()) },
        next: None,
    }.redact();
    assert!(!format!("{qualified:?}").contains("canary"));
    assert!(!format!("{ordinary:?}").contains("canary"));
}
