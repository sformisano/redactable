---
name: redactable-derive-selection
description: "Use when choosing or changing a Redactable derive for an owned Rust type. Decide between structured, display-only, dual, and public output from actual consumers; do not use this as an API reference."
metadata:
  skillcatalog/display_name: "Redactable Derive Selection"
  skillcatalog/author: "Salvatore Formisano"
  skillcatalog/created_at: "2026-04-29T15:18:46Z"
  skillcatalog/updated_at: "2026-09-30T00:00:00Z"
---
# Redactable Derive Selection

For Redactable 0.14, choose from the output the caller needs and the containing
types that must use it. Do not select a derive merely to satisfy a trait error.

## Choose the smallest sufficient output

| Need | Decision |
| --- | --- |
| Preserve a structured value for redacted serialization or traversal | Choose `Sensitive`. |
| Render a message or error without requiring a structured projection | Choose `SensitiveDisplay`. |
| Both structured and template output from the same disclosure decisions | Choose `SensitiveDual`. |
| Entire structured output is deliberately public | Consider `NotSensitive` only after auditing that complete output. |
| Existing display output is deliberately public | Consider `NotSensitiveDisplay`; also audit its passthrough use in structural containers. |

Use a separate log-view type when one type would otherwise serve incompatible
audiences or require a second producer implementation. A dual derive is useful
when both outputs are needed, not simply because it performs more checks.

## Assess the consequences

- Structural producers clone, redact, and serialize. Consider cost, borrow
  conflicts, and whether the source type can support those operations. Prefer a
  small projection for large, locked, or unsuitable foreign values.
- Do not derive `Sensitive` or `SensitiveDual` on a type implementing `Drop`.
  It is unsupported even when all fields are `Copy` and compilation succeeds.
  Select an output projection without that destructor.
- `SensitiveDisplay` checks only referenced fields. When a field is added,
  review every path that can expose it. Keep display-only when omission is
  intentional and no structured output is required; choose dual only when a
  structural consumer also needs redaction.
- Public derives are assertions, not inspections. `NotSensitive` serializes
  the original, so wrapping a nested sensitive type in it bypasses that type's
  structural policies. Audit the full serialization. For `NotSensitiveDisplay`,
  audit both its display text and any structural passthrough.
- Ordinary `Display` and `Error` are separate contracts. Pairing a sensitive
  display derive with `thiserror` does not change `thiserror`'s raw field
  formatting. Inspect that output before any error-reporting integration uses it.

## Respond to a declaration error

First decide whether the field is sensitive, explicitly public, or a nested
type with its own behavior. Preserve that decision while fixing the type bounds
or choosing a projection. Never blanket-add public declarations during an
upgrade. A successful compile cannot validate the resulting disclosure.

A field policy on a nested structured type is usually the wrong ownership of
the decision. Let its own policies run instead. For an unsupported shape, read
the relevant trait contract before changing data ownership or adding a bypass.

## Mechanics

- [Derive contracts and generated traits](https://github.com/sformisano/redactable/blob/main/docs/reference.md#what-each-derive-generates)
- [Generic declarations](https://github.com/sformisano/redactable/blob/main/docs/reference.md#generic-declarations)
- [Destructor restriction](https://github.com/sformisano/redactable/blob/main/docs/reference.md#types-that-implement-drop)
- [Template syntax](https://github.com/sformisano/redactable/blob/main/README.md#template-syntax)
- [Upgrade instructions](https://github.com/sformisano/redactable/blob/main/docs/reference.md#upgrading)
