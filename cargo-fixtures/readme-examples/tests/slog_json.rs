use std::{fs, sync::Mutex};

use redactable::{Secret, Sensitive, ToRedacted, logging::Sink};
use serde::Serialize;
use serde_json::{Value, json};
use slog::{Drain, Logger};

#[test]
fn checked_user_and_snapshot_reach_the_json_writer_with_request_context() {
    const TOKEN: &str = "slog-json-credential-8bd7";

    #[derive(Clone, Sensitive, Serialize)]
    struct User {
        #[not_sensitive]
        id: u64,
        #[not_sensitive]
        roles: Vec<Vec<String>>,
        #[sensitive(Secret)]
        token: String,
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("auth.log");
    {
        let drain = slog_json::Json::default(fs::File::create(&path).unwrap());
        let root = Logger::root(Mutex::new(drain).fuse(), slog::o!("app" => "auth"));
        let request = Sink::Slog(root.new(slog::o!("request_id" => "r-42")));
        let user = User {
            id: 724,
            roles: vec![vec!["reader".into(), "auditor".into()]],
            token: TOKEN.into(),
        };
        redactable::info!(sink: &request, user; "signed in");
        let saved = user.to_redacted();
        redactable::info!(sink: &request, user = &saved; "snapshot");
    }

    let output = fs::read_to_string(path).unwrap();
    assert!(!output.contains(TOKEN));
    let records: Vec<Value> = output
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert_eq!(records.len(), 2);
    for (record, message) in records.iter().zip(["signed in", "snapshot"]) {
        assert_eq!(record["msg"], message);
        assert_eq!(record["app"], "auth");
        assert_eq!(record["request_id"], "r-42");
        assert_eq!(
            record["user"],
            json!({
                "id": 724, "roles": [["reader", "auditor"]], "token": "[REDACTED]"
            })
        );
    }
}
