// Qualified type paths intentionally exercise derive name resolution.
use redactable::BypassRedaction;
use redactable::{Redactable, RedactableWithFormatter, Sensitive, SensitiveDisplay, SensitiveDual};
use redactable::{Secret, SensitiveValue};

#[derive(Clone, serde::Serialize, Sensitive)]
pub struct QualifiedNode<T> {
    value: T,
    #[redactable(recursive)]
    next: Option<Box<crate::explicit_recursion::QualifiedNode<T>>>,
}

#[derive(Clone, serde::Serialize, Sensitive)]
pub enum QualifiedEnum<T> {
    Next(
        T,
        #[redactable(recursive)] Box<crate::explicit_recursion::QualifiedEnum<T>>,
    ),
    End(T),
}

type Alias<T> = AliasNode<T>;

#[derive(Clone, serde::Serialize, Sensitive)]
pub struct AliasNode<T> {
    value: T,
    #[redactable(recursive)]
    next: Option<Box<Alias<T>>>,
}

#[derive(Clone, serde::Serialize, Sensitive)]
pub struct MutualA<T> {
    value: T,
    #[redactable(recursive)]
    next: Option<Box<MutualB<T>>>,
}

#[derive(Clone, serde::Serialize, Sensitive)]
pub struct MutualB<T> {
    value: T,
    #[redactable(recursive)]
    next: Option<Box<MutualA<T>>>,
}

#[derive(SensitiveDisplay)]
#[error("qualified {value:?} {next:?}")]
pub struct QualifiedDisplayNode<T> {
    value: T,
    #[redactable(recursive)]
    next: Option<Box<crate::explicit_recursion::QualifiedDisplayNode<T>>>,
}

#[derive(SensitiveDisplay)]
pub enum QualifiedDisplayEnum<T> {
    #[error("next {0:?} {1:?}")]
    Next(
        T,
        #[redactable(recursive)] Box<crate::explicit_recursion::QualifiedDisplayEnum<T>>,
    ),
    #[error("end {0:?}")]
    End(T),
}

type DisplayAlias<T> = AliasDisplayNode<T>;

#[derive(SensitiveDisplay)]
#[error("alias {value:?} {next:?}")]
pub struct AliasDisplayNode<T> {
    value: T,
    #[redactable(recursive)]
    next: Option<Box<DisplayAlias<T>>>,
}

#[derive(SensitiveDisplay)]
#[error("a {value:?} {next:?}")]
pub struct DisplayMutualA<T> {
    value: T,
    #[redactable(recursive)]
    next: Option<Box<DisplayMutualB<T>>>,
}

#[derive(SensitiveDisplay)]
#[error("b {value:?} {next:?}")]
pub struct DisplayMutualB<T> {
    value: T,
    #[redactable(recursive)]
    next: Option<Box<DisplayMutualA<T>>>,
}

#[derive(Clone, serde::Serialize, SensitiveDual)]
#[error("dual {value:?} {next:?}")]
pub struct QualifiedDualNode<T> {
    value: T,
    #[redactable(recursive)]
    next: Option<Box<crate::explicit_recursion::QualifiedDualNode<T>>>,
}

pub fn exercise() {
    let _ = QualifiedNode {
        value: SensitiveValue::<String, Secret>::from(String::from("secret")),
        next: None,
    }
    .redact();
    let _ = QualifiedEnum::Next(
        SensitiveValue::<String, Secret>::from(String::from("secret")),
        Box::new(QualifiedEnum::End(SensitiveValue::<String, Secret>::from(
            String::from("secret"),
        ))),
    )
    .redact();
    let _ = AliasNode {
        value: SensitiveValue::<String, Secret>::from(String::from("secret")),
        next: None,
    }
    .redact();
    let _ = MutualA {
        value: SensitiveValue::<String, Secret>::from(String::from("secret")),
        next: None,
    }
    .redact();
    let _ = MutualB {
        value: SensitiveValue::<String, Secret>::from(String::from("secret")),
        next: None,
    }
    .redact();
    let _ = MutualA {
        value: BypassRedaction::from(String::from("public")),
        next: Some(Box::new(MutualB {
            value: BypassRedaction::from(String::from("public")),
            next: None,
        })),
    }
    .redact();
    let _ = QualifiedDisplayNode {
        value: SensitiveValue::<String, Secret>::from(String::from("secret")),
        next: None,
    }
    .redacted_display()
    .to_string();
    let _ = QualifiedDisplayEnum::Next(
        SensitiveValue::<String, Secret>::from(String::from("secret")),
        Box::new(QualifiedDisplayEnum::End(
            SensitiveValue::<String, Secret>::from(String::from("secret")),
        )),
    )
    .redacted_display()
    .to_string();
    let _ = AliasDisplayNode {
        value: SensitiveValue::<String, Secret>::from(String::from("secret")),
        next: None,
    }
    .redacted_display()
    .to_string();
    let _ = DisplayMutualA {
        value: SensitiveValue::<String, Secret>::from(String::from("secret")),
        next: None,
    }
    .redacted_display()
    .to_string();
    let _ = DisplayMutualB {
        value: SensitiveValue::<String, Secret>::from(String::from("secret")),
        next: None,
    }
    .redacted_display()
    .to_string();
    let _ = QualifiedDualNode {
        value: SensitiveValue::<String, Secret>::from(String::from("secret")),
        next: None,
    }
    .redact();
}
