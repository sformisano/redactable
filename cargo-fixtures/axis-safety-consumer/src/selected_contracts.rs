use redactable::{
    NotSensitiveJsonExt, RedactableWithFormatter, RedactedOutput, Sensitive, SensitiveDisplay,
    ToRedactedOutput, UncheckedRedactedSummary,
};
use serde::{Serialize, Serializer, ser::Error};
use serde_json::json;

use crate::models::FullMaskOutput;

impl ToRedactedOutput for FullMaskOutput {
    fn to_redacted_output(&self) -> RedactedOutput {
        // This is an intentional log projection, not raw response serialization.
        json!({
            "account_id": self.account_id.redacted_display().to_string(),
            "owner_name": "[REDACTED]",
        })
        .not_sensitive_json()
        .to_redacted_output()
    }
}

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

impl ToRedactedOutput for OwnerLookup {
    fn to_redacted_output(&self) -> RedactedOutput {
        self.0
            .as_ref()
            .map(|_| "[REDACTED:owner]")
            .not_sensitive_json()
            .to_redacted_output()
    }
}

// Same sources, plus crates/reference/library/application/src/effects.rs.
// Each wrapper deliberately suppresses its inner value and option presence.
#[derive(Serialize)]
pub struct RecordedDecision(pub Option<String>);

impl ToRedactedOutput for RecordedDecision {
    fn to_redacted_output(&self) -> RedactedOutput {
        UncheckedRedactedSummary::new("[REDACTED:recorded-decision]".to_owned())
            .to_redacted_output()
    }
}

pub struct AccountDetailsValidation(pub String);

impl ToRedactedOutput for AccountDetailsValidation {
    fn to_redacted_output(&self) -> RedactedOutput {
        UncheckedRedactedSummary::new("[REDACTED:account-details-validation]".to_owned())
            .to_redacted_output()
    }
}

#[derive(Serialize)]
pub struct AccountView {
    pub owner: String,
    pub funds: u64,
    pub version: u64,
}

pub struct AccountOwnership(pub Option<AccountView>);

impl ToRedactedOutput for AccountOwnership {
    fn to_redacted_output(&self) -> RedactedOutput {
        UncheckedRedactedSummary::new("[REDACTED:account-ownership]".to_owned())
            .to_redacted_output()
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
#[redactable(output = json)]
pub struct SerializationFailure;

impl Serialize for SerializationFailure {
    fn serialize<S: Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
        Err(S::Error::custom("fixture serialization failure"))
    }
}
