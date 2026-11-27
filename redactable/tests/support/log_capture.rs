use log::{
    Record,
    kv::{Error, Key, Value, VisitSource},
};
use serde_json::{Map, Value as JsonValue};

#[derive(Default)]
struct Fields(Map<String, JsonValue>);

impl<'kvs> VisitSource<'kvs> for Fields {
    fn visit_pair(&mut self, key: Key<'kvs>, value: Value<'kvs>) -> Result<(), Error> {
        self.0.insert(
            key.as_str().to_owned(),
            serde_json::to_value(value).unwrap(),
        );
        Ok(())
    }
}

pub fn fields(record: &Record<'_>) -> JsonValue {
    let mut fields = Fields::default();
    record.key_values().visit(&mut fields).unwrap();
    JsonValue::Object(fields.0)
}
