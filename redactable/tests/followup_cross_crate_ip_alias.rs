//! Downstream proof for cross-crate aliases through a renamed dependency.

use std::{path::PathBuf, process::Command};

use tempfile::Builder;

#[test]
fn cross_crate_ip_map_alias_fails_with_the_targeted_workaround() {
    const PROVIDER: &str =
        include_str!("../../cargo-fixtures/renamed-policy/alias-provider/src/lib.rs");
    const CONSUMER: &str =
        include_str!("../../cargo-fixtures/renamed-policy/src/bin/rejected_alias.rs");
    assert!(PROVIDER.contains("pub type IpPeers = HashMap<IpAddr, String>"));
    assert!(CONSUMER.contains("use alias_provider::IpPeers"));
    assert!(CONSUMER.contains("peers: IpPeers"));

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../cargo-fixtures/renamed-policy/Cargo.toml");
    // Nested Cargo needs its own target while the parent test holds a target lock.
    let owner = Builder::new().prefix("rd-alias-").tempdir().unwrap();
    let target = owner.path().join("target");
    let output = Command::new(env!("CARGO"))
        .args([
            "check",
            "--offline",
            "--manifest-path",
            manifest.to_str().expect("UTF-8 fixture manifest path"),
            "--bin",
            "rejected_alias",
        ])
        .env("CARGO_TARGET_DIR", target)
        .output()
        .expect("cross-crate alias fixture cargo check executes");

    assert!(!output.status.success(), "unsafe IP map alias compiled");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("is not a supported map key for this IP-address policy"),
        "missing targeted map-key diagnostic:\n{stderr}"
    );
    assert!(
        stderr.contains("SensitiveValue<T, IpAddress>"),
        "missing targeted wrapper workaround:\n{stderr}"
    );
    owner.close().expect("remove target after child exits");
}
