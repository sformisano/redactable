use std::{collections::BTreeMap, io};

use flexi_logger::{DeferredNow, Logger};
use log::{Record, kv};
use redactable::{Secret, Sensitive, info};
use serde::{Serializer, ser::SerializeMap};

#[derive(Clone, Sensitive, serde::Serialize)]
struct User {
    #[not_sensitive]
    roles: Vec<String>,
    #[sensitive(Secret)]
    access_token: String,
}

fn sign_in() {
    let user = User {
        roles: vec!["reader".into()],
        access_token: "example-token".into(),
    };
    info!(user; "signed in");
}

fn main() -> Result<(), flexi_logger::FlexiLoggerError> {
    let _logger = Logger::try_with_str("info")?.format(json_log).start()?;
    sign_in();
    Ok(())
}

#[derive(Default)]
struct Fields<'a>(BTreeMap<kv::Key<'a>, kv::Value<'a>>);

impl<'a> kv::VisitSource<'a> for Fields<'a> {
    fn visit_pair(&mut self, key: kv::Key<'a>, value: kv::Value<'a>) -> Result<(), kv::Error> {
        self.0.insert(key, value);
        Ok(())
    }
}

fn json_log(out: &mut dyn io::Write, now: &mut DeferredNow, record: &Record<'_>) -> io::Result<()> {
    let mut fields = Fields::default();
    record
        .key_values()
        .visit(&mut fields)
        .map_err(io::Error::other)?;
    let mut serializer = serde_json::Serializer::new(out);
    let mut event = serializer.serialize_map(None)?;
    event.serialize_entry("timestamp", &now.format_rfc3339())?;
    event.serialize_entry("level", record.level().as_str())?;
    event.serialize_entry("target", record.target())?;
    event.serialize_entry("msg", record.args())?;
    event.serialize_entry("data", &fields.0)?;
    event.end()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flexi_logger::FileSpec;
    use serde_json::{Value, json};

    #[test]
    fn writes_the_message_and_all_structured_fields() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("auth.log");
        let logger = Logger::try_with_str("info")?
            .format(json_log)
            .log_to_file(FileSpec::try_from(&path)?)
            .start()?;

        sign_in();
        info!(msg = None::<()>, data = None::<()>; "optional fields");
        info!("started");
        logger.flush();

        let output = std::fs::read_to_string(path)?;
        assert!(!output.contains("example-token"));
        let records: Vec<Value> = output
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        assert_eq!(records.len(), 3);
        assert_eq!(records[0]["msg"], "signed in");
        assert_eq!(
            records[0]["data"],
            json!({
                "user": {"access_token": "[REDACTED]", "roles": ["reader"]}
            })
        );
        assert_eq!(records[0]["level"], "INFO");
        assert_eq!(
            records[0]["target"],
            module_path!().trim_end_matches("::tests")
        );
        assert!(records[0]["timestamp"].is_string());
        assert_eq!(records[1]["msg"], "optional fields");
        assert_eq!(records[1]["data"], json!({"msg": null, "data": null}));
        assert_eq!(records[2]["msg"], "started");
        assert_eq!(records[2]["data"], json!({}));
        Ok(())
    }
}
