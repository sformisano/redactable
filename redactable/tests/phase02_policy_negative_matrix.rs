//! Generated downstream compile matrix for direct-only built-in policy leaves.

use std::collections::HashSet;

#[path = "support/rustc_json.rs"]
mod rustc_json;

#[path = "phase02_policy_negative_matrix/matrix.rs"]
mod matrix;

use matrix::{
    EXPECTED_GRID_FINGERPRINT, EXPECTED_NEGATIVE_CELLS, REQUIRED_POSITIVE_CONTROLS, cargo_check,
    cargo_run, fingerprint, fixture_dir, grid_fingerprint, negative_source,
    positive_control_fingerprint, positive_source, validate_positive_source, write_fixture,
};
use rustc_json::compiler_error_lines;

#[test]
fn direct_only_policy_leaf_matrix_rejects_every_recursive_cell() {
    let directory = fixture_dir();
    let (negative, cells) = negative_source();
    let identities: HashSet<_> = cells.iter().map(|cell| cell.id.as_str()).collect();
    assert_eq!(cells.len(), EXPECTED_NEGATIVE_CELLS);
    assert_eq!(identities.len(), EXPECTED_NEGATIVE_CELLS);
    assert_eq!(
        grid_fingerprint(&cells),
        EXPECTED_GRID_FINGERPRINT,
        "matrix cell semantics changed; audit field/policy/derive/source axes before updating its fingerprint"
    );

    let positive_source = positive_source();
    validate_positive_source(&positive_source).expect("positive source contract must be intact");
    write_fixture(&directory, &positive_source);
    let positive = cargo_run(&directory);
    assert!(
        positive.status.success(),
        "positive/custom/generic controls failed:\n{}",
        String::from_utf8_lossy(&positive.stderr)
    );

    write_fixture(&directory, &negative);
    let output = cargo_check(&directory, true);
    assert!(
        !output.status.success(),
        "negative matrix unexpectedly compiled"
    );
    let error_lines: HashSet<_> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(compiler_error_lines)
        .flatten()
        .collect();
    for cell in cells {
        let attributable_line =
            (cell.first_line..=cell.last_line).find(|line| error_lines.contains(line));
        assert!(
            attributable_line.is_some(),
            "negative matrix cell {} on generated lines {}..={} has no attributable error-level diagnostic",
            cell.id,
            cell.first_line,
            cell.last_line
        );
    }
}

#[test]
fn matrix_integrity_fingerprints_detect_semantic_mutation_and_control_deletion() {
    let (_, cells) = negative_source();
    let original = grid_fingerprint(&cells);
    let mut mutated: Vec<_> = cells
        .iter()
        .map(|cell| cell.semantic_descriptor.clone())
        .collect();
    mutated[0].push_str("|mutant=changed-field-type");
    assert_ne!(original, fingerprint(mutated));

    let complete = positive_control_fingerprint();
    let shortened = fingerprint(REQUIRED_POSITIVE_CONTROLS[..7].iter().map(
        |(id, definition, exercise)| format!("id={id}|definition={definition}|exercise={exercise}"),
    ));
    assert_ne!(complete, shortened);

    let positive = positive_source();
    let mutant = positive.replacen("struct CustomBTreeMap {", "struct CustomMap {", 1);
    assert!(
        validate_positive_source(&mutant).is_err(),
        "control mutation must fail the real positive gate"
    );
}
