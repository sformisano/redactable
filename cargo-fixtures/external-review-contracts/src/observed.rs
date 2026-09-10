use std::fmt::{Arguments, Debug, Display, Formatter, Result as FmtResult};
use std::sync::atomic::Ordering;

use redactable::{Redactable, RedactableMapper, RedactableWithMapper, Secret, Sensitive};
use serde::{Serialize, Serializer};
use slog::{Key, Result as SlogResult, SerdeValue, Serializer as SlogSerializer};

use crate::{RAW_CLONES, RAW_DEBUGS, RAW_DISPLAYS, RAW_REDACTIONS, RAW_SERIALIZATIONS};

pub struct Observed(pub String);

impl Clone for Observed {
    fn clone(&self) -> Self {
        RAW_CLONES.fetch_add(1, Ordering::SeqCst);
        Self(self.0.clone())
    }
}

impl Debug for Observed {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        RAW_DEBUGS.fetch_add(1, Ordering::SeqCst);
        formatter.debug_tuple("Observed").field(&self.0).finish()
    }
}

impl Display for Observed {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        RAW_DISPLAYS.fetch_add(1, Ordering::SeqCst);
        formatter.write_str(&self.0)
    }
}

impl Serialize for Observed {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        RAW_SERIALIZATIONS.fetch_add(1, Ordering::SeqCst);
        serializer.serialize_str(&self.0)
    }
}

impl RedactableWithMapper for Observed {
    fn redact_with<M: RedactableMapper>(mut self, mapper: &M) -> Self {
        RAW_REDACTIONS.fetch_add(1, Ordering::SeqCst);
        self.0 = mapper.map_sensitive::<_, Secret>(self.0);
        self
    }
}

impl Redactable for Observed {}

#[derive(Clone, serde::Serialize, Sensitive)]
pub struct ObservedEvent {
    pub value: Observed,
}

pub struct CapturingSerializer;

impl SlogSerializer for CapturingSerializer {
    fn emit_arguments(&mut self, _key: Key, _value: &Arguments<'_>) -> SlogResult {
        Ok(())
    }

    fn emit_serde(&mut self, _key: Key, _value: &dyn SerdeValue) -> SlogResult {
        Ok(())
    }
}
