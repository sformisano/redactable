use redactable::__private::PolicyFieldRef;
use redactable::{policy::RecursivePolicyKind, PolicyApplicableRef, RedactableMapper, RedactableWithFormatter, RedactionPolicy, Secret, SensitiveDisplay};

#[derive(Debug)]
struct Leaf(String);

impl PolicyApplicableRef for Leaf {
    type Output = String;

    fn apply_policy_ref<P, M>(&self, _mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        P::policy().apply_to(&self.0)
    }
}

#[derive(SensitiveDisplay)]
#[error("{value}")]
struct Combined<T> where Option<T>: PolicyFieldRef<Secret>, <Option<T> as PolicyFieldRef<Secret>>::Output: RedactableWithFormatter {
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
