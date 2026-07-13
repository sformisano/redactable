#[test]
fn unified_feature_emits_all_private_root_impls() {
    assert!(enabler::slog_is_enabled());
    consumer_normal::assert_private_paths_and_emitters();
    consumer_renamed::assert_private_paths_and_emitters();
}

#[test]
fn workspace_metadata_has_one_redactable_identity_and_enabler_slog_edge() {
    use std::{path::Path, process::Command};

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_manifest = manifest_dir
        .parent()
        .expect("topology-check must be directly inside the fixture workspace")
        .join("Cargo.toml");
    let output = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--manifest-path",
        ])
        .arg(&workspace_manifest)
        .output()
        .expect("cargo metadata must run for the fixture workspace");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata must emit JSON");
    let packages = metadata["packages"]
        .as_array()
        .expect("metadata packages must be an array");
    let redactable_packages: Vec<_> = packages
        .iter()
        .filter(|package| package["name"] == "redactable")
        .collect();
    assert_eq!(
        redactable_packages.len(),
        1,
        "fixture must resolve exactly one redactable package identity"
    );
    let redactable_id = redactable_packages[0]["id"]
        .as_str()
        .expect("redactable package must have an ID");

    let enabler = packages
        .iter()
        .find(|package| package["name"] == "enabler")
        .expect("fixture metadata must contain enabler");
    let enabler_id = enabler["id"]
        .as_str()
        .expect("enabler package must have an ID");
    let enabler_redactable_dependencies: Vec<_> = enabler["dependencies"]
        .as_array()
        .expect("enabler dependencies must be an array")
        .iter()
        .filter(|dependency| dependency["name"] == "redactable")
        .collect();
    assert_eq!(
        enabler_redactable_dependencies.len(),
        1,
        "enabler must have exactly one redactable dependency edge"
    );
    assert!(
        enabler_redactable_dependencies[0]["features"]
            .as_array()
            .expect("dependency features must be an array")
            .iter()
            .any(|feature| feature == "slog"),
        "enabler's redactable dependency edge must request slog"
    );

    let resolve_nodes = metadata["resolve"]["nodes"]
        .as_array()
        .expect("metadata resolve nodes must be an array");
    let enabler_node = resolve_nodes
        .iter()
        .find(|node| node["id"] == enabler_id)
        .expect("resolved graph must contain enabler");
    let resolved_redactable_edges: Vec<_> = enabler_node["deps"]
        .as_array()
        .expect("resolved enabler dependencies must be an array")
        .iter()
        .filter(|dependency| dependency["pkg"] == redactable_id)
        .collect();
    assert_eq!(
        resolved_redactable_edges.len(),
        1,
        "enabler must resolve exactly one edge to the unique redactable package"
    );
    let redactable_node = resolve_nodes
        .iter()
        .find(|node| node["id"] == redactable_id)
        .expect("resolved graph must contain the unique redactable package");
    assert!(
        redactable_node["features"]
            .as_array()
            .expect("resolved features must be an array")
            .iter()
            .any(|feature| feature == "slog"),
        "the unique resolved redactable node must enable slog"
    );
}
