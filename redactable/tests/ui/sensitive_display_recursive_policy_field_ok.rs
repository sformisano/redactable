use redactable::{
    PolicyFormat, PolicyDisplay, PolicyFormattingOutput, RedactableMapper,
    RedactableWithFormatter, RedactionPolicy, Secret, SensitiveDisplay,
    policy::RecursivePolicyKind,
};

#[derive(Debug)]
struct Leaf(String);

impl PolicyFormat for Leaf {
    type Output = String;

    fn apply_policy_for_formatting<P, M>(&self, _mapper: &M) -> PolicyFormattingOutput<String>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        PolicyFormattingOutput::Value(P::policy().apply_to(&self.0))
    }
}

// `recursive` suppresses the inferred field bound, so the declaration states it.
#[derive(SensitiveDisplay)]
#[error("{value}")]
struct Combined<T>
where
    Option<T>: PolicyDisplay<Secret>,
{
    #[sensitive(Secret)]
    #[redactable(recursive)]
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
