---
name: redactable-wrappers-and-escape-hatches
description: "Use when deciding whether a sensitive leaf should carry its policy, adapting a foreign value, or assessing a Redactable bypass or raw accessor. Covers justification and scope of escape hatches, not wrapper API syntax."
metadata:
  skillcatalog/display_name: "Redactable Wrappers And Escape Hatches"
  skillcatalog/author: "Salvatore Formisano"
  skillcatalog/created_at: "2026-04-29T15:18:46Z"
  skillcatalog/updated_at: "2026-10-25T00:00:00Z"
---
# Redactable Wrappers And Escape Hatches

For Redactable 0.15, choose a wrapper to express a disclosure decision, not to
hide a trait error. A bypass is an explicit public-data assertion.

## Keep a policy with a leaf when needed

Prefer `SensitiveValue<T, P>` when a sensitive leaf travels independently of its
containing type or direct formatting is a realistic mistake. A field attribute
governs the containing type's output; it does not protect direct access to a bare
field. The wrapper's `Debug` applies its policy, but its serialization stays raw.
Choose the policy from a concrete confidentiality requirement. An operational
ID, title or message does not need a secret wrapper merely because it is text
or comes from a caller. A typed projection can retain useful parts of a locator
while excluding credential components.

Treat a structured foreign value as an atomic leaf only if a local policy can
account for every sensitive part. Its structural and text implementations can
differ: audit both. A wrapper does not discover or walk nested annotations.
Use a separate local projection when only a few approved fields are needed.
If type erasure has removed a domain's field policies, recover a producer from
the owning mapping before observing its values. Otherwise make that omission
explicit while retaining available operation metadata. Do not replace nested
policies with raw serialization or describe absent policy information as proof
that the entire value is confidential.

## Keep a bypass as narrow as its justification

For a custom logging projection, compare the consumer version's supported
output representations before settling on a bypass. A named view can derive
`Sensitive` when its fields still need policies, or `NotSensitive` when its
complete serialized projection is already approved for that output audience.
Keep construction of a prepared view with the owner that selects and protects
its contents. Neither a public derive nor a bypass checks that those decisions
are correct. Declaring the original raw payload or nested sensitive fields
public removes their protection.

For a field in a type you own, an explicit public field declaration is usually
clearer than changing the field's type. Use `BypassRedaction` when the value
itself must satisfy a redaction bound and its entire passthrough is justified.
Neither form walks nested sensitive fields.

At an output boundary, select a format-specific bypass only after reviewing
that complete representation. `Debug`, `Display`, and JSON may reveal different
data. A debug bypass around request metadata, an error context, or an SDK object
requires inspection of the actual formatter, not trust in its type name.

For an authored public summary, prefer `BypassDisplayRedaction` in new code.
It does not inspect or sanitize the string. Check interpolation sources and
expected content, including whether an empty summary loses needed diagnostics.
When replacing deprecated `BypassTextRedaction`, review the changed `Debug`
formatting, including literal newlines; this is not merely a rename.

A named application view owns a selected output contract. A wrapper that only
duplicates an upstream type's ownership or trait plumbing adds no such contract.
Use the upstream wrapper when it already meets that need. A format-specific
bypass remains appropriate for one-off prepared output when another application
type adds no useful meaning. Do not replace a real redacting projection with a
passthrough just because their trait sets look similar.

## Follow raw values after extraction

Allow `.expose()`, `.expose_mut()`, or `.into_inner()` when an operation needs the
raw value. Trace its downstream formatting, error construction, and diagnostic
serialization before accepting the access. Consuming extraction discards the
wrapper, so later code no longer carries its policy.

For each bypass or raw accessor, establish why the operation needs it and inspect
downstream uses. When it can affect diagnostic output, require a focused test of
that output. Keep unexplained disclosure paths open as findings and prefer a
narrower projection. Raw access used only for business computation does not need
a diagnostic test merely because an accessor appears.

## Mechanics

- [JSON output-view example](https://github.com/sformisano/redactable/blob/main/README.md#json-payloads-need-an-output-view)
- [Wrapper contracts and deprecation differences](https://github.com/sformisano/redactable/blob/main/docs/reference.md#wrapper-contracts)
- [Foreign-type implementation example](https://github.com/sformisano/redactable/blob/main/README.md#foreign-types)
- [Attribute versus wrapper behavior](https://github.com/sformisano/redactable/blob/main/README.md#protecting-individual-fields)
- [Replacing a local compatibility wrapper](https://github.com/sformisano/redactable/blob/main/docs/reference.md#migrating-a-local-compatibility-wrapper)
