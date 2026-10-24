---
name: redactable-field-policies
description: "Use when deciding what a Redactable field may disclose or reviewing a built-in or custom policy. Covers partial visibility, public declarations, dynamic data, and container disclosure; excludes derive and logging setup."
metadata:
  skillcatalog/display_name: "Redactable Field Policies"
  skillcatalog/author: "Salvatore Formisano"
  skillcatalog/created_at: "2026-04-29T15:18:46Z"
  skillcatalog/updated_at: "2026-10-24T00:00:00Z"
---
# Redactable Field Policies

For Redactable 0.15, choose field disclosure from the intended audience and the
value's meaning. Confirm the consumer's locked version before applying library
contracts. A policy name does not establish the right disclosure.

## Preserve useful context for the audience

Identify the output, its audience, and stated domain confidentiality requirements
before choosing policies. Restricted operator logs and public outputs can need
different projections of the same data. Access and retention remain host duties.

In restricted review diagnostics, preserve useful names, branches, IDs, titles,
labels, commit messages, paths, comments, and relevant review content by default.
Mask concrete credentials or authentication tokens, unnecessary personal data,
and values covered by a stated domain confidentiality requirement. Financial
Account data can need protection without making ordinary review context
confidential.

A value is not secret merely because it is `String`, free-form, caller-supplied,
internal, or from a private repository. The possibility of an embedded secret
does not justify masking a whole field. Where credentials actually enter a value,
select a boundary projection that protects them while retaining useful context.
Redactable applies declared policies; it does not detect secrets in content.

Keep operational identities, cursor positions, and provenance labels or locators
useful for correlation. Keep concrete credentials and domain-confidential values
out of those representations. Typed request keys and filters retain their nested
field policies; their diagnostic purpose does not make every field public.

For erased data, use a mapping-owned projection that knows its domain policy.
When no such projection exists, state an explicit omission reason and retain
available identity, version, source, and shape metadata. Erasure alone does not
establish that every original value is confidential.

Choose omission, truncation, and collection limits separately to control volume.
State size or relevance limits and omitted counts without calling them secrecy
policies. Preserve original business values and raw serialization where those
interfaces are supported.

## Choose disclosure deliberately

- For a protected value, prefer full masking when partial visibility has no
  stated diagnostic purpose.
  A policy named `Token` preserves a suffix; it is not interchangeable with
  `Secret`. Likewise, `Pii` does not recognize personal information in text.
- When partially masking a protected value, justify each retained fragment.
  An email domain, a short identifier, or a suffix can reveal identity or enable
  correlation. Decide whether that value belongs in the output at all before
  choosing a masking window.
- Exercise custom windows on invented but realistic empty, short, boundary,
  long, and Unicode inputs. Built-in keep policies fully mask values at or below
  their window; just above it, most of the value may remain visible. Assert
  exact expected output independently of the policy implementation.
- Assess `#[not_sensitive]` against the output paths that use it. Structural
  passthrough retains the whole value; a display-only field exposes the selected
  formatter's output. Audit that representation, including nested data it emits.
  Concrete personal-data or confidentiality requirements can protect IDs and
  timestamps too. A field's primitive type alone establishes neither secrecy nor
  public disclosure.
- Let nested declared types apply their own policies. Use a leaf policy where
  the whole value has one meaning; do not use an outer public declaration to
  silence missing support for a sensitive inner value.

## Check the representation

Text and typed IP policies disclose different fragments. For example, the same
address `1.2.3.4` becomes `***.3.4` as text but `0.0.0.4` as a typed IP. Choose
the representation and policy together; also assess any preserved port.

Traversal leaves map keys unchanged. Before accepting sensitive keys in logs,
check the resolved library and enabled features against the selected output.
Where available, `mask-map-keys` masks keys in `Sensitive` and `SensitiveDual`
producer JSON, including text adapted from JSON-only output. It does not change
templates, direct `Debug`, or public bypass producers. Verify the emitted output;
without key masking, redesign the projection so keys become policy-controlled
fields. Redacting map values alone does not protect the map. The
[map-key output contract](https://github.com/sformisano/redactable/blob/main/docs/reference.md#map-key-output)
defines the serialization and public-field limits.

Redacted set elements may become equal and collapse. Use a sequence projection
if the output needs to preserve cardinality, and decide whether revealing that
cardinality is itself acceptable. Scalar replacement can also create ordinary
values such as zero; do not feed that projection back into business decisions.

Dynamic JSON is opaque during structural redaction. Prefer a typed projection
when useful selected fields are needed. Declaring arbitrary JSON public exposes
future contents as well as today's sample. Generated structural `Debug` can
print an unannotated JSON field raw, so assess that path separately.

Verify representative useful and protected values together. Assert useful values
remain visible and protected values are absent from the configured sink output.
Check text, structured output, and actual `Debug` paths separately. Preserve
original values in business processing and supported raw serialization tests.
Include previous/current values and legitimate unknown vocabulary when the
observed contract accepts them. A mask-presence assertion alone is insufficient.

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
