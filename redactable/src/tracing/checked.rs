use crate::RedactedValue;

#[doc(hidden)]
#[macro_export]
macro_rules! __redactable_emit_tracing {
    (@level Error) => { $crate::tracing::__Level::ERROR };
    (@level Warn) => { $crate::tracing::__Level::WARN };
    (@level Info) => { $crate::tracing::__Level::INFO };
    (@level Debug) => { $crate::tracing::__Level::DEBUG };
    (@level Trace) => { $crate::tracing::__Level::TRACE };
    (@field [] ($value:expr)) => {
        $crate::tracing::__JsonField::record(&$crate::tracing::__JsonField::new(
            $crate::__redactable_field!(json $value)
        ))
    };
    (@field [%] ($value:expr)) => { $crate::__redactable_field!(text $value) };
    (@field [?] ($value:expr)) => { $crate::__redactable_field!(text $value) };
    ($level:ident, $destination:expr, [$($key:ident [$($mode:tt)?] ($value:expr)),*], $message:expr) => {
        $crate::tracing::__event!(
            $crate::__redactable_emit_tracing!(@level $level),
            { $($key = $crate::__redactable_emit_tracing!(@field [$($mode)?] ($value))),* },
            "{}", $message
        )
    };
}

#[cfg(not(all(feature = "tracing-valuable", tracing_unstable)))]
pub struct JsonField(String);

#[cfg(not(all(feature = "tracing-valuable", tracing_unstable)))]
impl JsonField {
    pub fn new(value: &RedactedValue) -> Self {
        Self(serde_json::to_string(value).unwrap_or_else(|_| {
            serde_json::Value::from(crate::policy::REDACTED_PLACEHOLDER).to_string()
        }))
    }

    pub fn record(&self) -> &str {
        &self.0
    }
}

#[cfg(all(feature = "tracing-valuable", tracing_unstable))]
pub use structured::JsonField;

#[cfg(all(feature = "tracing-valuable", tracing_unstable))]
mod structured {
    use super::RedactedValue;
    use serde_json::{Number, Value as Json};
    use valuable::{Listable, Mappable, Valuable, Value, Visit};

    // The subscriber visits each child while the stored JSON is borrowed.
    pub struct JsonField<'a>(Node<'a>);

    enum Node<'a> {
        Object(&'a serde_json::Map<String, Json>),
        Array(&'a [Json]),
        Message(&'static str, &'a str),
        Scalar(Value<'a>),
        // Valuable has no arbitrary-precision number type.
        NumberText(String),
    }

    impl<'a> JsonField<'a> {
        pub fn new(value: &'a RedactedValue) -> Self {
            if let Some(json) = value.structured() {
                return Self::from_json(json);
            }
            let (key, message) = value.message_field();
            Self(Node::Message(key, message))
        }

        pub fn record(&self) -> Value<'_> {
            self.as_value()
        }

        fn from_json(json: &'a Json) -> Self {
            Self(match json {
                Json::Object(map) => Node::Object(map),
                Json::Array(items) => Node::Array(items),
                Json::String(s) => Node::Scalar(Value::String(s)),
                Json::Bool(b) => Node::Scalar(Value::Bool(*b)),
                Json::Null => Node::Scalar(Value::Unit),
                Json::Number(n) => Self::number(n),
            })
        }

        fn number(n: &Number) -> Node<'a> {
            let value = n
                .as_u64()
                .map(Value::U64)
                .or_else(|| n.as_i64().map(Value::I64))
                .or_else(|| n.as_u128().map(Value::U128))
                .or_else(|| n.as_i128().map(Value::I128))
                .or_else(|| {
                    let float = n.as_f64()?;
                    (Number::from_f64(float).as_ref() == Some(n)).then_some(Value::F64(float))
                });
            value.map_or_else(|| Node::NumberText(n.to_string()), Node::Scalar)
        }
    }

    impl Valuable for JsonField<'_> {
        fn as_value(&self) -> Value<'_> {
            match &self.0 {
                Node::Object(_) | Node::Message(..) => Value::Mappable(self),
                Node::Array(_) => Value::Listable(self),
                Node::Scalar(value) => *value,
                Node::NumberText(s) => Value::String(s),
            }
        }

        fn visit(&self, visitor: &mut dyn Visit) {
            match &self.0 {
                Node::Object(map) => {
                    for (key, value) in *map {
                        visitor.visit_entry(Value::String(key), Self::from_json(value).as_value());
                    }
                }
                Node::Array(items) => {
                    for item in *items {
                        visitor.visit_value(Self::from_json(item).as_value());
                    }
                }
                Node::Message(key, text) => {
                    visitor.visit_entry(Value::String(key), Value::String(text));
                }
                Node::Scalar(_) | Node::NumberText(_) => visitor.visit_value(self.as_value()),
            }
        }
    }

    impl Mappable for JsonField<'_> {
        fn size_hint(&self) -> (usize, Option<usize>) {
            match &self.0 {
                Node::Object(map) => map.iter().size_hint(),
                Node::Message(..) => (1, Some(1)),
                _ => (0, Some(0)),
            }
        }
    }

    impl Listable for JsonField<'_> {
        fn size_hint(&self) -> (usize, Option<usize>) {
            match &self.0 {
                Node::Array(items) => items.iter().size_hint(),
                _ => (0, Some(0)),
            }
        }
    }
}
