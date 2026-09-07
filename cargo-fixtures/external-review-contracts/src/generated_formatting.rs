use redactable::__private::{PolicyApplicableRefForGeneratedFormatting, PolicyKindDebugFormatting};
use redactable::{Secret, SecretPolicyKind, SensitiveDisplay};

#[derive(SensitiveDisplay)]
#[error("{value}")]
pub struct GenericLibraryFormatting<T> {
    #[sensitive(Secret)]
    pub value: T,
}

#[derive(SensitiveDisplay)]
#[error("{value:?}")]
pub struct GenericGenerated<T>
where
    T: PolicyApplicableRefForGeneratedFormatting,
    SecretPolicyKind: PolicyKindDebugFormatting<Secret, T>,
{
    #[sensitive(Secret)]
    pub value: T,
}
