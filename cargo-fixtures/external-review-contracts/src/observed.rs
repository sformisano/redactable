use std::fmt;
use std::sync::atomic::Ordering;

use redactable::{RedactableMapper, RedactableWithMapper, Secret, Sensitive};
use serde::Serialize;

use crate::{RAW_CLONES, RAW_DEBUGS, RAW_DISPLAYS, RAW_REDACTIONS, RAW_SERIALIZATIONS};

pub struct Observed(pub String);

impl Clone for Observed {
    fn clone(&self) -> Self {
        RAW_CLONES.fetch_add(1, Ordering::SeqCst);
        Self(self.0.clone())
    }
}

impl fmt::Debug for Observed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        RAW_DEBUGS.fetch_add(1, Ordering::SeqCst);
        formatter.debug_tuple("Observed").field(&self.0).finish()
    }
}

impl fmt::Display for Observed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        RAW_DISPLAYS.fetch_add(1, Ordering::SeqCst);
        formatter.write_str(&self.0)
    }
}

impl Serialize for Observed {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
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

#[derive(Sensitive)]
pub struct ObservedEvent {
    pub value: Observed,
}

pub struct CapturingSerializer;

impl slog::Serializer for CapturingSerializer {
    fn emit_arguments(&mut self, _key: slog::Key, _value: &fmt::Arguments<'_>) -> slog::Result {
        Ok(())
    }

    fn emit_serde(&mut self, _key: slog::Key, _value: &dyn slog::SerdeValue) -> slog::Result {
        Ok(())
    }
}
