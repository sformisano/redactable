//! Subprocess regression for conflict-safe formatting under `panic = "abort"`.

use std::{path::PathBuf, process::Command};

#[test]
fn secret_and_ip_generic_refcell_aliases_are_conflict_safe_with_panic_abort() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../cargo-fixtures/panic-abort-refcell/Cargo.toml");
    let target = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target/cargo-fixtures/panic-abort-refcell");
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
}

#[test]
fn documented_clone_backed_adapter_panics_abort_without_emitting_the_canary() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../cargo-fixtures/panic-abort-refcell/Cargo.toml");
    let target = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target/cargo-fixtures/panic-abort-refcell");
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
}

#[test]
fn consuming_adapters_survive_a_stuck_refcell_borrow_flag_without_emitting_the_canary() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../cargo-fixtures/panic-abort-refcell/Cargo.toml");
    let target = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target/cargo-fixtures/panic-abort-refcell");
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
        "consuming-output",
        "consuming-json",
        "consuming-tracing-debug",
    ] {
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
    }
}
