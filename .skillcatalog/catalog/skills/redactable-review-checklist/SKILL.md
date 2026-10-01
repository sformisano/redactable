---
name: redactable-review-checklist
description: "Use for a design or code-review pass over existing Redactable usage or a Redactable upgrade. Trace disclosure paths and assess evidence; does not trigger on unrelated Rust code merely because it handles data."
metadata:
  skillcatalog/display_name: "Redactable Review Checklist"
  skillcatalog/author: "Salvatore Formisano"
  skillcatalog/created_at: "2026-04-29T15:18:46Z"
  skillcatalog/updated_at: "2026-09-30T00:00:00Z"
---
# Redactable Review Checklist

For Redactable 0.14, review the path to observable output, not just the presence
of annotations. Confirm the consumer's locked version first.

## Review questions

1. **What can leave the application?** Trace logs, spans, error chains, debug
   dumps, and diagnostic serialization. Identify the exact conversion and sink.
   Look for raw field formatting, ordinary error `Display`, raw Serde output,
   and the low-level free `redact` function on these paths.
2. **What disclosure was approved?** Challenge public declarations, retained
   policy fragments, map keys, identifiers, and collection counts against real
   data sources and audience needs. A numeric field is not automatically public.
3. **Does the containing type apply that decision?** An outer public declaration
   can bypass nested sensitive fields. Check the entire output representation,
   including custom formatters, serializers, and policy implementations.
4. **Is the output path appropriate?** Check structural versus display needs,
   destructor restrictions, clone/borrow costs, and actual logger output. Review
   an unannotated JSON field's direct `Debug` separately from structural redaction.
5. **What changed outside compiler coverage?** For a newly added field omitted
   from a display template, review its other outputs. Intentional omission is a
   valid display-only design. Require structural redaction only when that path
   is needed. During upgrades, challenge bulk public declarations and inspect
   deprecated-wrapper formatting changes.
6. **Where does raw data escape?** For each bypass and raw accessor, establish
   why it is necessary and trace downstream diagnostics. An unexplained bypass
   remains a finding; a successful compile does not resolve it.
7. **What proves the result?** Require independently written expected output for
   the relevant paths, realistic short/window-boundary policy samples, and actual
   sink capture when an integration changes. Pair shape checks with exact values.
   Check useful diagnostic content as well as forbidden disclosure.

## Scope findings to evidence

Do not report every `format!`, public field, or omitted template field as a leak.
Establish the sensitive source, reachable output path, and unwanted disclosure.
If evidence is missing, state what must be inspected or exercised instead of
claiming a proven leak or accepting a claimed safe path.

Generated masking does not switch off in consumer tests or with the `testing`
feature. Expect the same per-field behavior there; do not request obsolete tests
that reveal annotated raw data. Partial policy output and public fields remain
visible by design and still require judgment.

Use this compact finding shape:

```text
Finding: <specific unwanted disclosure or lost diagnostic>
Path: <source -> operation -> output>
Change: <narrowest correction and its tradeoff>
Evidence: <current code or output; missing proof if any>
Regression check: <expected result that catches this failure>
```

## Mechanics

- [Protection boundary](https://github.com/sformisano/redactable/blob/main/README.md#what-redaction-protects)
- [Generated output behavior](https://github.com/sformisano/redactable/blob/main/docs/reference.md#generated-debug-and-ordinary-display)
- [Output tests](https://github.com/sformisano/redactable/blob/main/docs/reference.md#testing-redacted-output)
- [Upgrade contracts](https://github.com/sformisano/redactable/blob/main/docs/reference.md#upgrading)
