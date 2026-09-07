use redactable::{Secret, Sensitive, SensitiveDisplay, SensitiveDual};
use serde::Serialize;

#[derive(Clone, serde::Serialize, Sensitive)]
pub struct Node {
    pub next: Option<Box<Node>>,
}

#[derive(Clone, serde::Serialize, Sensitive)]
pub enum RecursiveEnum {
    Next(Box<RecursiveEnum>),
    End,
}

// `#[redactable(recursive)]` combined with a `#[sensitive(Secret)]` field.
// Both structural traversal (`.redact()`) and the consuming adapters are
// exercised below. The consuming route used to be a compile error for this
// shape: the removed owned-capability hierarchy generated an owned traversal
// bound that did not honor the override, forming a trait-solver cycle
// (`E0275`). The adapters now route through `.redact()`, which honors it, so
// recursive types are supported on every route.
#[derive(Clone, Sensitive, Serialize)]
pub struct SecretRecursiveNode {
    #[sensitive(Secret)]
    pub secret: String,
    #[redactable(recursive)]
    pub next: Option<Box<SecretRecursiveNode>>,
}

#[derive(Clone, serde::Serialize, Sensitive)]
pub enum SecretRecursiveEnum {
    Next(#[redactable(recursive)] Box<SecretRecursiveEnum>),
    Secret(#[sensitive(Secret)] String),
}

#[derive(Clone, serde::Serialize, Sensitive)]
pub enum LeftEnum {
    Next(Box<RightEnum>),
    End,
}

#[derive(Clone, serde::Serialize, Sensitive)]
pub enum RightEnum {
    Next(Box<LeftEnum>),
    End,
}

#[derive(Clone, serde::Serialize, Sensitive)]
pub struct Left {
    pub right: Option<Box<Right>>,
}

#[derive(Clone, serde::Serialize, Sensitive)]
pub struct Right {
    pub left: Option<Box<Left>>,
}

#[derive(Clone, serde::Serialize, Sensitive)]
pub struct GenericNode<T> {
    pub value: T,
    pub next: Option<Box<GenericNode<T>>>,
}

#[derive(SensitiveDisplay)]
#[error("node {next:?}")]
pub struct DisplayNode {
    pub next: Option<Box<DisplayNode>>,
}

#[derive(SensitiveDisplay)]
#[error("left {right:?}")]
pub struct DisplayLeft {
    pub right: Option<Box<DisplayRight>>,
}

#[derive(SensitiveDisplay)]
#[error("right {left:?}")]
pub struct DisplayRight {
    pub left: Option<Box<DisplayLeft>>,
}

#[derive(SensitiveDisplay)]
pub enum DisplayEnum {
    #[error("next {0:?}")]
    Next(Box<DisplayEnum>),
    #[error("end")]
    End,
}

#[derive(SensitiveDisplay)]
pub enum DisplayLeftEnum {
    #[error("next {0:?}")]
    Next(Box<DisplayRightEnum>),
    #[error("end")]
    End,
}

#[derive(SensitiveDisplay)]
pub enum DisplayRightEnum {
    #[error("next {0:?}")]
    Next(Box<DisplayLeftEnum>),
    #[error("end")]
    End,
}

#[derive(Clone, serde::Serialize, SensitiveDual)]
#[error("dual {next:?}")]
pub struct DualNode {
    pub next: Option<Box<DualNode>>,
}
