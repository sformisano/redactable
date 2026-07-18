use redactable::{RedactableMapper, RedactableWithFormatter, Secret, SensitiveDisplay};

#[derive(Debug)]
struct Leaf(String);

impl redactable::PolicyApplicableRef for Leaf {
    type Output = String;

    fn apply_policy_ref<P, M>(&self, _mapper: &M) -> Self::Output
    where
        P: redactable::RedactionPolicy,
        P::Kind: redactable::policy::RecursivePolicyKind,
        M: RedactableMapper,
    {
        P::policy().apply_to(&self.0)
    }
}

#[derive(SensitiveDisplay)]
#[error("{value}")]
struct Combined<T> {
    #[sensitive(Secret)]
    #[redactable(recursive, legacy_formatting)]
    value: Option<T>,
}

fn main() {
    assert_eq!(
        Combined {
            value: Some(Leaf(String::from("secret"))),
        }
        .redacted_display()
        .to_string(),
        "Some([REDACTED])"
    );
}
