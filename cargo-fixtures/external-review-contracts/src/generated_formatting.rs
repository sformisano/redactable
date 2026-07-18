use redactable::{Secret, SensitiveDisplay};

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
    T: redactable::__private::PolicyApplicableRefForGeneratedFormatting,
    redactable::SecretPolicyKind:
        redactable::__private::PolicyKindDebugFormatting<redactable::Secret, T>,
{
    #[sensitive(Secret)]
    pub value: T,
}
