//! Subprocess regression for conflict-safe formatting under `panic = "abort"`.

use std::{path::PathBuf, process::Command};

use tempfile::Builder;

#[test]
fn secret_and_ip_generic_refcell_aliases_are_conflict_safe_with_panic_abort() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../cargo-fixtures/panic-abort-refcell/Cargo.toml");
    // Nested Cargo needs its own target while the parent test holds a target lock.
    let owner = Builder::new().prefix("rd-abort-").tempdir().unwrap();
    let target = owner.path().join("target");
    let output = Command::new(env!("CARGO"))
        .args([
            "run",
            "--locked",
            "--quiet",
            "--manifest-path",
            manifest.to_str().expect("UTF-8 fixture manifest path"),
        ])
        .env("CARGO_TARGET_DIR", target)
        .output()
        .expect("panic-abort fixture cargo run executes");

    assert!(
        output.status.success(),
        "panic-abort RefCell formatting failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    owner.close().expect("remove target after child exits");
}

#[test]
fn documented_clone_backed_adapter_panics_abort_without_emitting_the_canary() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../cargo-fixtures/panic-abort-refcell/Cargo.toml");
    // Nested Cargo needs its own target while the parent test holds a target lock.
    let owner = Builder::new().prefix("rd-abort-").tempdir().unwrap();
    let target = owner.path().join("target");
    let build = Command::new(env!("CARGO"))
        .args([
            "build",
            "--locked",
            "--quiet",
            "--manifest-path",
            manifest.to_str().expect("UTF-8 fixture manifest path"),
        ])
        .env("CARGO_TARGET_DIR", &target)
        .output()
        .expect("panic-abort fixture cargo build executes");
    assert!(
        build.status.success(),
        "panic-abort fixture build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    let binary = target
        .join("debug")
        .join("redactable-panic-abort-refcell-fixture");
    for mode in [
        "borrowed-output",
        "borrowed-json",
        "borrowed-tracing-debug",
        "borrowed-tracing-display",
    ] {
        let output = Command::new(&binary)
            .arg(mode)
            .output()
            .expect("panic-abort adapter mode executes");
        assert!(!output.status.success(), "{mode} must abort");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(combined.contains("mutably borrowed"), "{mode}: {combined}");
        assert!(
            !combined.contains("borrowed-adapter-panic-abort-canary"),
            "{mode} emitted the raw canary: {combined}"
        );
    }
    owner.close().expect("remove target after child exits");
}

#[test]
fn the_consuming_tracing_adapter_survives_a_stuck_refcell_borrow_flag_without_emitting_the_canary()
{
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../cargo-fixtures/panic-abort-refcell/Cargo.toml");
    // Nested Cargo needs its own target while the parent test holds a target lock.
    let owner = Builder::new().prefix("rd-abort-").tempdir().unwrap();
    let target = owner.path().join("target");
    let build = Command::new(env!("CARGO"))
        .args([
            "build",
            "--locked",
            "--quiet",
            "--manifest-path",
            manifest.to_str().expect("UTF-8 fixture manifest path"),
        ])
        .env("CARGO_TARGET_DIR", &target)
        .output()
        .expect("panic-abort fixture cargo build executes");
    assert!(
        build.status.success(),
        "panic-abort fixture build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    let binary = target
        .join("debug")
        .join("redactable-panic-abort-refcell-fixture");
    // `into_tracing_redacted_debug` is the only consuming adapter left: the sink
    // value always clones (D9), so its routes now abort like the borrowed ones.
    let mode = "consuming-tracing-debug";
    let output = Command::new(&binary)
        .arg(mode)
        .output()
        .expect("panic-abort consuming adapter mode executes");
    assert!(output.status.success(), "{mode} must not abort");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains("borrowed-adapter-panic-abort-canary"),
        "{mode} emitted the raw canary: {combined}"
    );
    owner.close().expect("remove target after child exits");
}
