use redactable::{
    BypassJsonRedaction, BypassTextRedaction, RedactedValue, Sensitive, SensitiveDisplay,
    ToRedacted,
};
use serde::{Serialize, Serializer, ser::Error};

// Axis sources at revision 14417ae77286e45a7d4dbbd8e674a9a6cc091397:
// crates/reference/library/application/src/use_cases/account_onboarding/effects.rs
// crates/reference/library/application/src/use_cases/account_onboarding/load_owner_endpoint.rs
#[derive(Clone, Serialize)]
#[serde(transparent)]
pub struct OwnerLookup(pub Option<String>);

impl OwnerLookup {
    pub fn into_inner(self) -> Option<String> {
        self.0
    }
}

impl ToRedacted for OwnerLookup {
    fn to_redacted(&self) -> RedactedValue {
        let selected = self.0.as_ref().map(|_| "[REDACTED:owner]");
        BypassJsonRedaction(&selected).to_redacted()
    }
}

// Same sources, plus crates/reference/library/application/src/effects.rs.
// Each wrapper deliberately suppresses its inner value and option presence.
#[derive(Serialize)]
pub struct RecordedDecision(pub Option<String>);

impl ToRedacted for RecordedDecision {
    fn to_redacted(&self) -> RedactedValue {
        BypassTextRedaction("[REDACTED:recorded-decision]".to_owned())
            .to_redacted()
    }
}

pub struct AccountDetailsValidation(pub String);

impl ToRedacted for AccountDetailsValidation {
    fn to_redacted(&self) -> RedactedValue {
        BypassTextRedaction("[REDACTED:account-details-validation]".to_owned())
            .to_redacted()
    }
}

#[derive(Serialize)]
pub struct AccountView {
    pub owner: String,
    pub funds: u64,
    pub version: u64,
}

pub struct AccountOwnership(pub Option<AccountView>);

impl ToRedacted for AccountOwnership {
    fn to_redacted(&self) -> RedactedValue {
        BypassTextRedaction("[REDACTED:account-ownership]".to_owned())
            .to_redacted()
    }
}

// Axis: crates/reference/library/application/src/support/capability_proof.rs
// at revision 14417ae77286e45a7d4dbbd8e674a9a6cc091397.
#[derive(Serialize, SensitiveDisplay)]
/// value={value}
pub struct CapabilitySummary {
    #[not_sensitive]
    pub value: u64,
    pub allowed: bool,
}

#[derive(Clone, Sensitive)]
pub struct SerializationFailure;

impl Serialize for SerializationFailure {
    fn serialize<S: Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
        Err(S::Error::custom("fixture serialization failure"))
    }
}
