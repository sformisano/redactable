//! Test-only slog serializer that retains emitted values for exact assertions.

use std::{cell::RefCell, collections::HashMap, fmt::Arguments};

use serde_json::Value as JsonValue;

pub(crate) struct CapturingSerializer {
    captured: RefCell<HashMap<String, CapturedValue>>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum CapturedValue {
    Str(String),
    Bool(bool),
    I64(i64),
    U64(u64),
    F64(f64),
    Unit,
    None,
    Serde(JsonValue),
}

impl CapturingSerializer {
    pub(crate) fn new() -> Self {
        Self {
            captured: RefCell::new(HashMap::new()),
        }
    }

    pub(crate) fn get(&self, key: &str) -> Option<CapturedValue> {
        self.captured.borrow().get(key).cloned()
    }
}

impl slog::Serializer for CapturingSerializer {
    fn emit_arguments(&mut self, key: slog::Key, val: &Arguments<'_>) -> slog::Result {
        self.captured
            .borrow_mut()
            .insert(key.into(), CapturedValue::Str(val.to_string()));
        Ok(())
    }

    fn emit_str(&mut self, key: slog::Key, val: &str) -> slog::Result {
        self.captured
            .borrow_mut()
            .insert(key.into(), CapturedValue::Str(val.into()));
        Ok(())
    }

    fn emit_bool(&mut self, key: slog::Key, val: bool) -> slog::Result {
        self.captured
            .borrow_mut()
            .insert(key.into(), CapturedValue::Bool(val));
        Ok(())
    }

    fn emit_i64(&mut self, key: slog::Key, val: i64) -> slog::Result {
        self.captured
            .borrow_mut()
            .insert(key.into(), CapturedValue::I64(val));
        Ok(())
    }

    fn emit_u64(&mut self, key: slog::Key, val: u64) -> slog::Result {
        self.captured
            .borrow_mut()
            .insert(key.into(), CapturedValue::U64(val));
        Ok(())
    }

    fn emit_f64(&mut self, key: slog::Key, val: f64) -> slog::Result {
        self.captured
            .borrow_mut()
            .insert(key.into(), CapturedValue::F64(val));
        Ok(())
    }

    fn emit_unit(&mut self, key: slog::Key) -> slog::Result {
        self.captured
            .borrow_mut()
            .insert(key.into(), CapturedValue::Unit);
        Ok(())
    }

    fn emit_none(&mut self, key: slog::Key) -> slog::Result {
        self.captured
            .borrow_mut()
            .insert(key.into(), CapturedValue::None);
        Ok(())
    }

    fn emit_serde(&mut self, key: slog::Key, val: &dyn slog::SerdeValue) -> slog::Result {
        let json = serde_json::to_value(val.as_serde()).unwrap_or(JsonValue::Null);
        self.captured
            .borrow_mut()
            .insert(key.into(), CapturedValue::Serde(json));
        Ok(())
    }
}

pub(crate) fn serialize_to_capture<V: slog::Value, S: slog::Serializer>(
    value: &V,
    key: &'static str,
    serializer: &mut S,
) {
    static RS: slog::RecordStatic<'static> = slog::record_static!(slog::Level::Info, "");
    let args = format_args!("");
    let record = slog::Record::new(&RS, &args, slog::b!());
    value.serialize(&record, key, serializer).unwrap();
}
