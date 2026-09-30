# Redactable skill catalog

The editable catalog lives in [catalog](catalog/). It was imported from
[`sformisano/redactable-skills`](https://github.com/sformisano/redactable-skills/tree/b710173f91f6c11c6c73f9a2b3fa18534077c7f5)
and reviewed against Redactable 0.14. Skills guide decisions; the
[README](../README.md) and [reference](../docs/reference.md) own API mechanics.

Catalog ID `redactable-skills`, all six skill IDs, stack `redactable`, and bundle
`redactable-skills` are unchanged. The stack still contains all six skills.
Sibling mentions no longer declare circular installation dependencies: each
skill stands alone and links to the product documentation it needs. Skill links
are absolute repository URLs so they remain usable after installation elsewhere.
They point at current documentation; use the consumer's locked revision when its
version differs from the catalog's 0.14 target.

## Publication status

Source has moved; publication has not switched. The standalone repository remains
the active installation source and retains its frozen 0.13 compatibility snapshot:

```sh
skc catalog add https://github.com/sformisano/redactable-skills.git
```

Make content changes only here. Do not independently edit the old skills or
advertise the library repository as an installation source yet. Local catalog
validation is not evidence of app support for an inlined catalog.

## Switch publication only after app verification

Once a released app supports `.skillcatalog/catalog`, verify both paths using
disposable app configuration and delivery targets:

1. Freshly register the library source, install the existing bundle, and check
   that exactly the six expected skills arrive with working documentation links.
2. Start from an installation of the standalone source. Follow the app's
   supported source-change procedure while preserving catalog, stack, bundle,
   and skill IDs. Update and verify content replacement, no duplicate catalog,
   no lost selections, and no stale delivered skills.
3. Record the app version, library revision, commands or UI actions, and observed
   results with the publication change. A command-line catalog validation alone
   does not satisfy either installation check.
4. Update installation instructions and any catalog registry/profile source URLs
   together. Leave a permanent pointer in the standalone README with the new
   source and upgrade instructions. Retire its obsolete publication files only
   after the update path passes; preserve Git history and existing release refs.

Until those checks pass, keep the old source registered. If either check fails,
defer the switch and preserve the compatibility snapshot. Do not maintain a
second edited catalog to work around missing app support.

## Maintenance and validation

When library behavior changes, inspect the skill that owns the affected decision:

| Skill | Decision | Mechanical contract |
| --- | --- | --- |
| `redactable-core-model` | Fit, protection limits, boundary placement | [Protection boundary](../README.md#what-redaction-protects) |
| `redactable-derive-selection` | Structured, text, dual, or public output | [Derive contracts](../docs/reference.md#what-each-derive-generates) |
| `redactable-field-policies` | What each field may reveal | [Policies](../README.md#policies-and-reference), [supported types](../docs/reference.md#supported-types) |
| `redactable-wrappers-and-escape-hatches` | Policy ownership, foreign types, bypasses | [Wrapper contracts](../docs/reference.md#wrapper-contracts) |
| `redactable-logging-boundaries` | Conversion, sink representation, cost | [Adapter contracts](../docs/reference.md#output-and-adapter-contracts) |
| `redactable-review-checklist` | Evidence and findings across an existing change | [Testing](../docs/reference.md#testing-redacted-output), [upgrades](../docs/reference.md#upgrading) |

Run these checks from the repository root, with `TMPDIR` set to an existing
task-owned directory with enough space:

```sh
bash .github/scripts/check-skillcatalog.sh
python3 .github/scripts/check-skill-links.py
cargo test --locked --doc --manifest-path cargo-fixtures/readme-examples/Cargo.toml
```

The catalog check uses a checksum-pinned SkillCatalog CLI and disposable config;
it does not register the catalog or change installed profiles. The link check
checks every skill's Markdown destinations and heading anchors against this
checkout, including absolute links to this repository. API examples live in the
product docs and run in the existing consumer doctest fixture. The former 0.13
skill-example harness remains only with the frozen standalone snapshot; it is
not a current-library validation gate.

Packaging checks do not validate judgment. Review changed guidance against code
and documentation, and exercise both a risky case and a valid counterexample.
For example, a bulk public declaration must be challenged, while an intentionally
omitted display-only field need not force a dual derive. Keep review results with
the change rather than treating a historical validation report as current proof.
