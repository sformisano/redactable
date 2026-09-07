use std::fmt::{Debug, Display, Formatter, Result as FmtResult};

use redactable::{
    __private::DeclaredFormatting, Pii, Redactable, RedactableMapper, RedactableWithFormatter,
    RedactableWithMapper, RedactedOutput, Secret, Sensitive, SensitiveDisplay, SensitiveDual,
    ToRedactedOutput, UncheckedRedactedSummary,
};
use serde::{Serialize, Serializer};

#[derive(Clone, Serialize, Sensitive)]
#[redactable(output = json)]
pub struct OwnershipOutput {
    #[sensitive(Secret)]
    pub owner_name: String,
    #[not_sensitive]
    pub approved: bool,
}

#[derive(Debug, Serialize)]
pub struct ForeignPublic {
    pub status: &'static str,
    pub attempt: u64,
}

impl Display for ForeignPublic {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(self.status)
    }
}

// Nominal private state follows Axis's
// crates/framework/internal/domain/contracts/src/aggregate/entity_id.rs,
// revision 14417ae77286e45a7d4dbbd8e674a9a6cc091397.
// The manual companion declares formatting without exposing field types.
#[derive(Clone)]
pub struct AccountId {
    raw: String,
    redacted: bool,
}

impl AccountId {
    pub fn new(raw: &str) -> Self {
        Self {
            raw: raw.to_owned(),
            redacted: false,
        }
    }
}

impl RedactableWithMapper for AccountId {
    fn redact_with<M: RedactableMapper>(mut self, _: &M) -> Self {
        self.redacted = true;
        self
    }
}

impl Redactable for AccountId {}

impl RedactableWithFormatter for AccountId {
    fn fmt_redacted(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("<redacted-aggregate-id>")
    }
}

impl DeclaredFormatting for AccountId {}

impl Debug for AccountId {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_tuple("AggregateId")
            .field(&self.redacted_display())
            .finish()
    }
}

impl Serialize for AccountId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.redacted {
            serializer.collect_str(&self.redacted_display())
        } else {
            serializer.serialize_str(&self.raw)
        }
    }
}

// Deliberately has no ToRedactedOutput: the ordinary field route is structural.
#[derive(Clone, Serialize, Sensitive)]
pub struct StructuralInput {
    pub account_id: AccountId,
    #[sensitive(Secret)]
    pub owner_name: String,
    #[not_sensitive]
    pub request_kind: &'static str,
}

#[derive(SensitiveDisplay)]
/// account_id={account_id}
pub struct EventSummary {
    pub account_id: AccountId,
    pub omitted_source: ForeignError,
}

#[derive(Debug)]
pub struct ForeignError(pub String);

// Source omission follows EndpointCommandError in Axis's
// crates/reference/library/application/src/use_cases/account_onboarding/create_account_endpoint.rs
// at revision 14417ae77286e45a7d4dbbd8e674a9a6cc091397.
#[derive(SensitiveDisplay)]
#[error("account command failed")]
pub struct EndpointError {
    pub source: ForeignError,
}

#[derive(Clone, Serialize, SensitiveDual)]
#[redactable(output = json)]
/// owner={owner_name}
pub struct DualOutput {
    #[sensitive(Secret)]
    pub owner_name: String,
    #[not_sensitive]
    pub approved: bool,
}

pub struct DivergentOutput;

impl RedactableWithFormatter for DivergentOutput {
    fn fmt_redacted(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("FORMATTER")
    }
}

impl ToRedactedOutput for DivergentOutput {
    fn to_redacted_output(&self) -> RedactedOutput {
        UncheckedRedactedSummary::new("SELECTED".to_owned()).to_redacted_output()
    }
}

// Axis's ChangeOwnerNameOutput structurally uses Pii but selects a full mask.
// Source: crates/reference/library/application/src/use_cases/account_profile_management/change_owner_name.rs
// at revision 14417ae77286e45a7d4dbbd8e674a9a6cc091397.
#[derive(Clone, Serialize, Sensitive)]
pub struct FullMaskOutput {
    pub account_id: AccountId,
    #[sensitive(Pii)]
    pub owner_name: String,
}
