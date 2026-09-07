//! Downstream compile proof for a Rust-keyword Cargo dependency alias.

use std::{fs, path::Path, process::Command};

use tempfile::Builder;

#[test]
fn keyword_alias_builds_default_slog_and_tracing_generated_paths() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("runtime crate is in the workspace root");
    let fixture_owner = Builder::new()
        .prefix("rd-keyword-")
        .tempdir()
        .expect("create owned keyword alias fixture under TMPDIR");
    let fixture = fixture_owner.path();
    fs::create_dir_all(fixture.join("src")).expect("create keyword alias fixture");

    let manifest = format!(
        r#"[package]
name = "keyword-alias-proof"
version = "0.0.0"
edition = "2024"
rust-version = "1.97"

[dependencies]
serde = {{ version = "1", features = ["derive"] }}

[dependencies.type]
package = "redactable"
path = {runtime_path:?}
features = ["slog", "tracing"]
"#,
        runtime_path = workspace.join("redactable")
    );
    fs::write(fixture.join("Cargo.toml"), manifest).expect("write keyword alias manifest");
    fs::write(
        fixture.join("src/main.rs"),
        r#"#![allow(dead_code)]

use core::fmt::{Display, Formatter, Result as FmtResult};
use r#type::{
    NotSensitiveDisplay, Sensitive, SensitiveDisplay,
    slog::SlogRedacted, tracing::TracingRedacted,
};

#[derive(Clone, serde::Serialize, Sensitive)]
struct SecretValue(#[sensitive(r#type::Secret)] String);

#[derive(SensitiveDisplay)]
#[error("{value}")]
struct DisplaySecret {
    #[sensitive(r#type::Secret)]
    value: String,
}

#[derive(NotSensitiveDisplay)]
struct PublicValue;

impl Display for PublicValue {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter.write_str("public")
    }
}

fn main() {
    fn slog<T: SlogRedacted>() {}
    fn tracing<T: TracingRedacted>() {}
    slog::<SecretValue>();
    slog::<DisplaySecret>();
    tracing::<SecretValue>();
    tracing::<DisplaySecret>();
}
"#,
    )
    .expect("write keyword alias source");

    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .args(["check", "--manifest-path"])
        .arg(fixture.join("Cargo.toml"))
        .arg("--quiet")
        .env("CARGO_TARGET_DIR", fixture.join("target"))
        .output()
        .expect("run keyword alias cargo check");

    fixture_owner
        .close()
        .expect("remove owned keyword alias fixture");
    assert!(
        output.status.success(),
        "keyword dependency alias did not compile:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
