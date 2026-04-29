# Holistic Redaction Review Fixes

Ticket: none
Date: 2026-04-30

## Plan

Validate each reported review finding against current code, tests, README content, and feature behavior before changing behavior. Preserve the core model: redaction is mostly opt-in, serialization stays raw unless explicitly redacted, and redaction is enforced at output or logging boundaries.

## Validation

Confirmed and fixed: 1, 2, 3, 4, 5, 6, 9, 10, 11, 13, 15, and 16.

Confirmed but intentionally kept with clearer documentation: 12 and 14. Derived redacted `Debug` remains a stronger generic placeholder instead of policy-shaped output. Empty strings still redact to `[REDACTED]`.

Not confirmed as code changes: 7 and 8. Current trybuild baselines are valid for the toolchain used here, apart from the new baselines added for this change. Strict clippy passed without needing the suspected `Duration::from_secs(60)` adjustment.

## Execution

The logging-boundary trait was narrowed so raw passthrough formatting no longer qualifies a value as certified logging-safe. `SensitiveDisplay` derives now implement the logging-safe output trait explicitly, while slog display adapters format through the display formatter path.

References:

- redactable/src/redaction/output.rs:38-127 ([open](../../redactable/src/redaction/output.rs#L38-L127), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable/src/redaction/output.rs#L38-L127))
- redactable-derive/src/lib.rs:125-136 ([open](../../redactable-derive/src/lib.rs#L125-L136), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable-derive/src/lib.rs#L125-L136))
- redactable/src/slog.rs:40-64 ([open](../../redactable/src/slog.rs#L40-L64), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable/src/slog.rs#L40-L64))
- redactable/src/slog.rs:220-247 ([open](../../redactable/src/slog.rs#L220-L247), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable/src/slog.rs#L220-L247))

`SensitiveDisplay` policy formatting now wraps policy-redacted container outputs for display, while keeping debug formatting aligned with the redacted value's ordinary `Debug`. Sparse positional placeholders, unsupported specifiers, and dynamic width or precision fail with macro-owned errors.

References:

- redactable/src/redaction/display.rs:71-95 ([open](../../redactable/src/redaction/display.rs#L71-L95), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable/src/redaction/display.rs#L71-L95))
- redactable/src/lib.rs:74-97 ([open](../../redactable/src/lib.rs#L74-L97), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable/src/lib.rs#L74-L97))
- redactable/src/redaction/mod.rs:28-42 ([open](../../redactable/src/redaction/mod.rs#L28-L42), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable/src/redaction/mod.rs#L28-L42))
- redactable-derive/src/redacted_display.rs:212-243 ([open](../../redactable-derive/src/redacted_display.rs#L212-L243), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable-derive/src/redacted_display.rs#L212-L243))
- redactable-derive/src/redacted_display.rs:289-409 ([open](../../redactable-derive/src/redacted_display.rs#L289-L409), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable-derive/src/redacted_display.rs#L289-L409))

IP address handling was moved back into the opt-in model. Unannotated IP and socket address fields pass through unchanged, while `#[sensitive(IpAddress)]` still redacts address components. The feature flag now enables the redaction surface it depends on.

References:

- redactable/Cargo.toml:16-29 ([open](../../redactable/Cargo.toml#L16-L29), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable/Cargo.toml#L16-L29))
- redactable/src/redaction/containers/ip_address.rs:14-138 ([open](../../redactable/src/redaction/containers/ip_address.rs#L14-L138), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable/src/redaction/containers/ip_address.rs#L14-L138))
- redactable-derive/src/transform.rs:91-132 ([open](../../redactable-derive/src/transform.rs#L91-L132), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable-derive/src/transform.rs#L91-L132))
- redactable-derive/src/types.rs:75-117 ([open](../../redactable-derive/src/types.rs#L75-L117), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable-derive/src/types.rs#L75-L117))

Documentation now matches the intended contracts: version snippets use `0.7`, `serde_json::Value` is documented as the main default-redact exception, IP types are documented as opt-in, raw serialization warnings are more prominent, and unsupported format syntax is called out.

References:

- README.md:119-128 ([open](../../README.md#L119-L128), [GitHub](https://github.com/sformisano/redactable/blob/main/README.md#L119-L128))
- README.md:340-366 ([open](../../README.md#L340-L366), [GitHub](https://github.com/sformisano/redactable/blob/main/README.md#L340-L366))
- README.md:638-682 ([open](../../README.md#L638-L682), [GitHub](https://github.com/sformisano/redactable/blob/main/README.md#L638-L682))
- README.md:830-899 ([open](../../README.md#L830-L899), [GitHub](https://github.com/sformisano/redactable/blob/main/README.md#L830-L899))
- redactable/src/redaction/json.rs:1-43 ([open](../../redactable/src/redaction/json.rs#L1-L43), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable/src/redaction/json.rs#L1-L43))
- redactable/src/redaction/wrappers.rs:23-40 ([open](../../redactable/src/redaction/wrappers.rs#L23-L40), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable/src/redaction/wrappers.rs#L23-L40))
- redactable/src/redaction/redact.rs:268-279 ([open](../../redactable/src/redaction/redact.rs#L268-L279), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable/src/redaction/redact.rs#L268-L279))

Release metadata was bumped for a patch release. The workspace and internal derive dependency now target `0.7.1`, and the project changelog summarizes the release contents.

References:

- Cargo.toml:5-7 ([open](../../Cargo.toml#L5-L7), [GitHub](https://github.com/sformisano/redactable/blob/main/Cargo.toml#L5-L7))
- redactable/Cargo.toml:31-32 ([open](../../redactable/Cargo.toml#L31-L32), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable/Cargo.toml#L31-L32))
- CHANGELOG.md:3-20 ([open](../../CHANGELOG.md#L3-L20), [GitHub](https://github.com/sformisano/redactable/blob/main/CHANGELOG.md#L3-L20))

## Tests

Added compile-pass and compile-fail coverage for the logging-safe boundary, `SensitiveDisplay` policy containers, sparse positional placeholders, dynamic formatting rejection, unsupported specifier rejection, and clearer `NonZero*` policy errors. Added integration coverage for IP passthrough versus annotated redaction, raw `SensitiveValue` serialization, and slog redaction before serialization.

References:

- redactable/src/redaction/containers/tests.rs:259-310 ([open](../../redactable/src/redaction/containers/tests.rs#L259-L310), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable/src/redaction/containers/tests.rs#L259-L310))
- redactable/tests/ui_to_redacted_output.rs:1-12 ([open](../../redactable/tests/ui_to_redacted_output.rs#L1-L12), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable/tests/ui_to_redacted_output.rs#L1-L12))
- redactable/tests/ui_sensitive_display.rs:1-49 ([open](../../redactable/tests/ui_sensitive_display.rs#L1-L49), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable/tests/ui_sensitive_display.rs#L1-L49))
- redactable/tests/ui_sensitive.rs:1-7 ([open](../../redactable/tests/ui_sensitive.rs#L1-L7), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable/tests/ui_sensitive.rs#L1-L7))
- redactable/tests/ui/to_redacted_output_certified_ok.rs:1-49 ([open](../../redactable/tests/ui/to_redacted_output_certified_ok.rs#L1-L49), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable/tests/ui/to_redacted_output_certified_ok.rs#L1-L49))
- redactable/tests/ui/to_redacted_output_raw_string_rejected.rs:1-8 ([open](../../redactable/tests/ui/to_redacted_output_raw_string_rejected.rs#L1-L8), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable/tests/ui/to_redacted_output_raw_string_rejected.rs#L1-L8))
- redactable/tests/ui/sensitive_display_policy_containers_ok.rs:1-48 ([open](../../redactable/tests/ui/sensitive_display_policy_containers_ok.rs#L1-L48), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable/tests/ui/sensitive_display_policy_containers_ok.rs#L1-L48))
- redactable/tests/ui/sensitive_display_sparse_positional_rejected.rs:1-9 ([open](../../redactable/tests/ui/sensitive_display_sparse_positional_rejected.rs#L1-L9), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable/tests/ui/sensitive_display_sparse_positional_rejected.rs#L1-L9))
- redactable/tests/ui/sensitive_display_dynamic_width_rejected.rs:1-9 ([open](../../redactable/tests/ui/sensitive_display_dynamic_width_rejected.rs#L1-L9), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable/tests/ui/sensitive_display_dynamic_width_rejected.rs#L1-L9))
- redactable/tests/ui/sensitive_display_unsupported_specifier_rejected.rs:1-9 ([open](../../redactable/tests/ui/sensitive_display_unsupported_specifier_rejected.rs#L1-L9), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable/tests/ui/sensitive_display_unsupported_specifier_rejected.rs#L1-L9))
- redactable/tests/ui/sensitive_nonzero_secret_rejected.rs:1-11 ([open](../../redactable/tests/ui/sensitive_nonzero_secret_rejected.rs#L1-L11), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable/tests/ui/sensitive_nonzero_secret_rejected.rs#L1-L11))
- redactable/tests/integration_wrappers.rs:63-83 ([open](../../redactable/tests/integration_wrappers.rs#L63-L83), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable/tests/integration_wrappers.rs#L63-L83))
- redactable/tests/integration_slog.rs:639-655 ([open](../../redactable/tests/integration_slog.rs#L639-L655), [GitHub](https://github.com/sformisano/redactable/blob/main/redactable/tests/integration_slog.rs#L639-L655))

Generated trybuild stderr baselines were added for the compile-fail cases:

- redactable/tests/ui/to_redacted_output_raw_string_rejected.stderr, generated trybuild compiler-output baseline.
- redactable/tests/ui/sensitive_display_sparse_positional_rejected.stderr, generated trybuild compiler-output baseline.
- redactable/tests/ui/sensitive_display_dynamic_width_rejected.stderr, generated trybuild compiler-output baseline.
- redactable/tests/ui/sensitive_display_unsupported_specifier_rejected.stderr, generated trybuild compiler-output baseline.
- redactable/tests/ui/sensitive_nonzero_secret_rejected.stderr, generated trybuild compiler-output baseline.

## Verification

Passed:

- `cargo +1.93.0 fmt --all -- --check`, with existing stable rustfmt warnings about unstable rustfmt settings.
- `cargo +1.93.0 clippy --all --all-targets --all-features -- -D warnings -D rust-2018-idioms -D rust-2021-compatibility -A deprecated -A dead-code`.
- `cargo +1.93.0 test --all-features --all-targets`.
- `cargo +1.93.0 test --doc --all-features`.
- `cargo check --no-default-features`.
- `cargo check --features policy`.
- `cargo check --no-default-features --features ip-address`.
- `cargo build --no-default-features --features json`.
- `cargo build --no-default-features --features tracing`.
- `cargo build --release`.
- `cargo build --release --all-features`.

Optional tools were unavailable in this environment:

- `cargo-audit`.
- `cargo-deny`.

## Outcome

The review findings that affected behavior are fixed without changing the crate's core model. Raw strings no longer satisfy the logging-safe output trait by accident, policy-redacted display containers work with `{field}`, IP types are opt-in again, feature-only builds are warning-free, and the workspace is prepared for the `0.7.1` crates.io release.

## Deferred

No follow-up code changes are required from this task.
