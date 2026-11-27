use flexi_logger::{FileSpec, Logger, json_format};
use redactable::{BypassDisplayRedaction, Secret, Sensitive, info, logging::Sink};
use serde_json::{Value, json};

#[derive(Clone, Sensitive, serde::Serialize)]
struct User {
    #[not_sensitive]
    roles: Vec<String>,
    #[sensitive(Secret)]
    access_token: String,
}

#[test]
fn writes_redacted_nested_fields() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("auth.log");
    let logger = Logger::try_with_str("info")?
        .format(json_format)
        .log_to_file(FileSpec::try_from(&path)?)
        .start()?;

    let user = User {
        roles: vec!["reader".into()],
        access_token: "example-token".into(),
    };
    info!(Sink::Log, user = &user, channel:% = BypassDisplayRedaction("web"); "signed in");
    logger.flush();

    let line = std::fs::read_to_string(path)?;
    let record: Value = serde_json::from_str(&line)?;
    assert_eq!(record["text"], "signed in");
    assert_eq!(
        record["kv"],
        json!({
            "channel": "web",
            "user": {"access_token": "[REDACTED]", "roles": ["reader"]}
        })
    );
    assert!(!line.contains(&user.access_token));
    Ok(())
}
