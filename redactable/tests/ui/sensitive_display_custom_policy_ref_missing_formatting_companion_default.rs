use redactable::{
    PolicyApplicableRef, RedactableMapper, RedactionPolicy, Secret, SensitiveDisplay,
    policy::RecursivePolicyKind,
};

#[derive(Debug)]
struct CustomLeaf;

impl PolicyApplicableRef for CustomLeaf {
    type Output = String;

    fn apply_policy_ref<P, M>(&self, _mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        "[REDACTED]".to_owned()
    }
}

#[derive(SensitiveDisplay)]
#[error("{value}")]
struct MissingCompanion {
    #[sensitive(Secret)]
    value: CustomLeaf,
}

fn main() {
    let _ = MissingCompanion { value: CustomLeaf };
}
