use redactable::{PolicyDebug, PolicyDisplay, Secret, SensitiveDisplay};
#[derive(SensitiveDisplay)]
#[error("{value}")]
pub struct GenericLibraryFormatting<T: PolicyDisplay<Secret>> {
    #[sensitive(Secret)]
    pub value: T,
}

#[derive(SensitiveDisplay)]
#[error("{value:?}")]
pub struct GenericGenerated<T>
where
    T: PolicyDebug<Secret>,
{
    #[sensitive(Secret)]
    pub value: T,
}
