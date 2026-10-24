---
name: redactable-logging-boundaries
description: "Use when designing or changing a logging, tracing, telemetry, or diagnostic path that uses Redactable. Decide where conversion occurs, which representation reaches the sink, and how to verify disclosure and runtime costs."
metadata:
  skillcatalog/display_name: "Redactable Logging Boundaries"
  skillcatalog/author: "Salvatore Formisano"
  skillcatalog/created_at: "2026-04-29T15:18:46Z"
  skillcatalog/updated_at: "2026-10-24T00:00:00Z"
---
# Redactable Logging Boundaries

For Redactable 0.15, trace the value from its source to the actual output writer.
Apply a redacted operation or reviewed adapter before sensitive data reaches
that writer, including error reports and ad hoc diagnostics.

## Make the boundary explicit

Prefer a `ToRedacted`-based interface for a custom output pipeline. It rejects
undeclared raw values, but admits public declarations and bypasses. Review those
declarations and the implementation; a trait bound alone proves no confidentiality.
The writer must use the resulting projection, not extract and format a raw field.
Retain the operation's useful identity, query, transition and outcome context.
A projection that replaces an entire request or result with a mask can satisfy
the trait while preventing diagnosis. Generic envelopes delegate typed keys,
filters and results to their own policies instead of discarding them.

Do not serialize or interpolate sensitive data into a string before conversion.
Neither a bypass wrapper nor the low-level free `redact(value)` function repairs
that string. Ordinary error `Display`, error chains, span fields, and debug
dumps need the same path inspection as explicit log statements.

## Choose the output the sink actually needs

- Use a structured producer when downstream tools need fields, and a display
  producer when a selected message is sufficient. A text accessor rendering
  compact JSON is still text to the sink. A text-only producer's `json()` is
  an object with a `message` field; it is not a scalar string. Assert the actual
  representation when composing nested projections.
- Use the named slog JSON adapter for a redacted object. Direct borrowed
  structural values emit a fixed placeholder; that protects content but can
  discard the diagnostics the caller expected. Inspect the drain's output.
  The [runnable slog example](https://github.com/sformisano/redactable/blob/main/README.md#slog)
  shows the field-preserving route and required nested-value drain features.
- Choose tracing text, redacted `Debug`, or structured valuable output from
  downstream requirements. Exercise the subscriber and feature configuration
  used by the application before claiming structured output works.
- `Sensitive` masks annotated fields in generated `Debug` and delegates other
  fields to their own `Debug`. `SensitiveDisplay` and `SensitiveDual` render
  policy-shaped templates. An unannotated opaque JSON field can therefore be
  visible through `Sensitive`'s direct `Debug` even though structural traversal
  replaces the whole payload with a mask. Use a typed diagnostic view to retain
  useful metadata and apply concrete field protection; do not make raw JSON
  public to recover lost context.

## Bound cost and failure behavior

Structural producers clone before redacting. Consider large payloads, shared
ownership, and live `RefCell` borrows before putting them on frequent or critical
paths. Borrowed display formatting has different behavior; a consuming adapter
can avoid the outer clone but not every clone during nested traversal.

An owned `RedactedValue` records conversion at construction. Borrowed formatting
and the slog text adapter can run again when formatted or emitted. Choose the
lifetime deliberately when source state or policy cost matters. Valuable
projections can expose interior-mutable redacted objects; do not assume the
wrapper reapplies redaction after caller-driven mutation.

Serialization errors replace the whole JSON output with a placeholder. Policies,
clones, formatters, and serializers can still panic. Do not turn a logging
failure into raw fallback output, and do not promise panic isolation.

Use `RedactedList` when item count needs a limit, but assess its visible omitted
count. It does not bound bytes, depth, allocations, or per-item policy work.
Set any additional resource limits at the application boundary. Output limits
control size and relevance separately from confidentiality; label omissions
and counts accordingly instead of calling all omitted content secret.

## Verify the emitted result

Capture the actual logger or subscriber output using synthetic sensitive values.
Assert both the expected useful fields and the absence of forbidden raw values.
Include realistic public context alongside protected values in the same record.
Check nested and before/after projections, error and fallback paths, and unchanged
business values and raw serialization where supported. Shape-only assertions or
the presence of a mask cannot establish useful, correctly protected output.

## Mechanics

- [Logging integration examples](https://github.com/sformisano/redactable/blob/main/README.md#integrations)
- [Output, timing, failure, and adapter contracts](https://github.com/sformisano/redactable/blob/main/docs/reference.md#output-and-adapter-contracts)
- [Collection output](https://github.com/sformisano/redactable/blob/main/docs/reference.md#bounded-list-output)
- [Testing redacted output](https://github.com/sformisano/redactable/blob/main/docs/reference.md#testing-redacted-output)
