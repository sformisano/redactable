---
name: redactable-field-policies
description: "Use when deciding what a Redactable field may disclose or reviewing a built-in or custom policy. Covers partial visibility, public declarations, dynamic data, and container disclosure; excludes derive and logging setup."
metadata:
  skillcatalog/display_name: "Redactable Field Policies"
  skillcatalog/author: "Salvatore Formisano"
  skillcatalog/created_at: "2026-04-29T15:18:46Z"
  skillcatalog/updated_at: "2026-09-30T00:00:00Z"
---
# Redactable Field Policies

For Redactable 0.14, decide what a field may reveal from its data source and the
output audience. The policy name is not evidence that the disclosure is safe.

## Choose disclosure deliberately

- Prefer full masking when partial visibility has no stated diagnostic purpose.
  A policy named `Token` preserves a suffix; it is not interchangeable with
  `Secret`. Likewise, `Pii` does not recognize personal information in text.
- Justify each retained fragment. An email domain, a short identifier, or a
  suffix can reveal identity or enable correlation. Decide whether that value
  belongs in the output at all before choosing a masking window.
- Exercise custom windows on invented but realistic empty, short, boundary,
  long, and Unicode inputs. Built-in keep policies fully mask values at or below
  their window; just above it, most of the value may remain visible. Assert
  exact expected output independently of the policy implementation.
- Assess `#[not_sensitive]` against the output paths that use it. Structural
  passthrough retains the whole value; a display-only field exposes the selected
  formatter's output. Audit that representation, including nested data it emits.
  Numeric IDs and timestamps can be sensitive too. A field's name or primitive
  type does not establish that its output is public.
- Let nested declared types apply their own policies. Use a leaf policy where
  the whole value has one meaning; do not use an outer public declaration to
  silence missing support for a sensitive inner value.

## Check the representation

Text and typed IP policies disclose different fragments. For example, the same
address `1.2.3.4` becomes `***.3.4` as text but `0.0.0.4` as a typed IP. Choose
the representation and policy together; also assess any preserved port.

Map keys are not redacted. If keys can contain sensitive data, redesign the
logging projection so those values become policy-controlled fields. Redacting
map values alone does not protect the map.

Redacted set elements may become equal and collapse. Use a sequence projection
if the output needs to preserve cardinality, and decide whether revealing that
cardinality is itself acceptable. Scalar replacement can also create ordinary
values such as zero; do not feed that projection back into business decisions.

Dynamic JSON is opaque during structural redaction. Prefer a typed projection
when useful selected fields are needed. Declaring arbitrary JSON public exposes
future contents as well as today's sample. Generated structural `Debug` can
print an unannotated JSON field raw, so assess that path separately.

## Custom policies and unsupported shapes

Use a custom policy only when its disclosure is clearer and better justified
than a built-in choice. Review both structural and formatted output; custom
implementations are responsible for every sensitive part they retain.

Support for traversal does not imply support for every policy annotation or
derive. Consult the type contracts before changing a field to make it compile.
In particular, do not turn a sensitive `NonZero` value or locked value public
because a policy cannot be applied directly; use a suitable output projection.

## Mechanics

- [Built-in and custom policies](https://github.com/sformisano/redactable/blob/main/README.md#policies-and-reference)
- [Supported types and policy constraints](https://github.com/sformisano/redactable/blob/main/docs/reference.md#supported-types)
- [Empty, short, and container behavior](https://github.com/sformisano/redactable/blob/main/docs/reference.md#precedence-and-edge-cases)
- [Custom formatting contract](https://github.com/sformisano/redactable/blob/main/docs/reference.md#custom-policy-formatting)
