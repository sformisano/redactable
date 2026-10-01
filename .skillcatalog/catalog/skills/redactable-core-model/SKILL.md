---
name: redactable-core-model
description: "Use when deciding whether Redactable fits a Rust data flow and where redaction belongs. Covers protection limits and boundary placement; use the focused skills for derive, policy, wrapper, logging, or review decisions."
metadata:
  skillcatalog/display_name: "Redactable Core Model"
  skillcatalog/author: "Salvatore Formisano"
  skillcatalog/created_at: "2026-04-29T15:18:46Z"
  skillcatalog/updated_at: "2026-09-30T00:00:00Z"
---
# Redactable Core Model

Use Redactable when typed Rust values need an explicit disclosure policy for
logs, diagnostics, or other selected output. This guidance targets 0.14; check
the consumer's locked version before applying it to older code.

## Decide what is being protected

- Name the output, its audience, and the data it may reveal before selecting a
  policy. A value acceptable in one diagnostic channel may be unsuitable in
  another. Use separate projections when their disclosure needs differ.
- Redact at the observation boundary. Keep raw application data for business
  operations that need it; do not replace stored values, queue payloads, or API
  inputs with redacted copies unless that is the intended product behavior.
- Redactable does not discover secrets, enforce access control, encrypt stored
  data, or erase raw values from memory. Ordinary field access and serialization
  can still expose them. Use separate protections for those requirements.
- Treat a redacted value as a selected disclosure, not proof of anonymity.
  Policy fragments, public identifiers, collection sizes, and relationships
  can still identify a person or reveal activity.

## Keep decisions with the data

Let a nested type own its field policies. Leave its containing field unannotated
when that behavior is wanted. A public declaration on the containing field
skips traversal, including the nested policies.

Use field attributes when the policy belongs to one containing representation.
Consider a policy-bearing leaf wrapper when the value travels independently and
accidental direct formatting is likely. Neither choice redacts raw serialization.

The compiler checks declarations on every structural field and every referenced
template field. It cannot determine whether a public declaration is true or a
policy reveals too much. Omitted fields in a display-only type are outside that
formatting path; review other uses of those fields without assuming they require
structural redaction.

## Recognize the limits

Require an explicit redacted operation or reviewed logging adapter on paths that
may carry sensitive data. A derive elsewhere in the object graph is insufficient.
The low-level free `redact(value)` function can leave raw leaves unchanged.
Generated `Debug` also differs by derive and field declaration; do not infer its
disclosure from the word “redacted.”

Do not introduce Redactable just to label data that never reaches an observed
output. Conversely, it cannot repair a pipeline that formats sensitive data
before reaching the redaction boundary. Trace the complete path first.

## Mechanics

- [Getting started and protection boundary](https://github.com/sformisano/redactable/blob/main/README.md#what-redaction-protects)
- [Traversal contracts](https://github.com/sformisano/redactable/blob/main/docs/reference.md#low-level-traversal)
- [Generated output behavior](https://github.com/sformisano/redactable/blob/main/docs/reference.md#generated-debug-and-ordinary-display)

The sibling skills divide the remaining decisions: `redactable-derive-selection`
owns output shape; `redactable-field-policies` owns disclosure;
`redactable-wrappers-and-escape-hatches` owns wrapper and bypass choices;
`redactable-logging-boundaries` owns delivery to a sink; and
`redactable-review-checklist` owns the final review pass.
