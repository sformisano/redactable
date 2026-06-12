use redactable::{IpAddress, Sensitive, SensitiveWithPolicy, TextRedactionPolicy};

#[derive(Clone)]
struct IpAddr(String);

impl SensitiveWithPolicy<IpAddress> for IpAddr {
    fn redact_with_policy(self, policy: &TextRedactionPolicy) -> Self {
        Self(policy.apply_to(&self.0))
    }

    fn redacted_string(&self, policy: &TextRedactionPolicy) -> String {
        policy.apply_to(&self.0)
    }
}

#[derive(Clone, Sensitive)]
struct BadPeer {
    #[sensitive(IpAddress)]
    peer: Option<IpAddr>,
}

fn main() {}
