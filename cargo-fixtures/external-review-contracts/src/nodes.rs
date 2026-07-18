use redactable::{Secret, Sensitive, SensitiveDisplay, SensitiveDual};
use serde::Serialize;

#[derive(Sensitive)]
pub struct Node {
    pub next: Option<Box<Node>>,
}

#[derive(Sensitive)]
pub enum RecursiveEnum {
    Next(Box<RecursiveEnum>),
    End,
}

// `#[redactable(recursive)]` combined with a `#[sensitive(Secret)]` field.
// Both the borrowed route (`.redact()`) and the consuming adapters are
// exercised below. The consuming route used to be a compile error for this
// shape: the removed owned-capability hierarchy generated an owned traversal
// bound that did not honor the override, forming a trait-solver cycle
// (`E0275`). The adapters now route through `.redact()`, which honors it, so
// recursive types are supported on every route.
#[derive(Sensitive, Serialize)]
pub struct SecretRecursiveNode {
    #[sensitive(Secret)]
    pub secret: String,
    #[redactable(recursive)]
    pub next: Option<Box<SecretRecursiveNode>>,
}

#[derive(Sensitive)]
pub enum SecretRecursiveEnum {
    Next(#[redactable(recursive)] Box<SecretRecursiveEnum>),
    Secret(#[sensitive(Secret)] String),
}

#[derive(Sensitive)]
pub enum LeftEnum {
    Next(Box<RightEnum>),
    End,
}

#[derive(Sensitive)]
pub enum RightEnum {
    Next(Box<LeftEnum>),
    End,
}

#[derive(Sensitive)]
pub struct Left {
    pub right: Option<Box<Right>>,
}

#[derive(Sensitive)]
pub struct Right {
    pub left: Option<Box<Left>>,
}

#[derive(Sensitive)]
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

#[derive(SensitiveDual)]
#[error("dual {next:?}")]
pub struct DualNode {
    pub next: Option<Box<DualNode>>,
}
