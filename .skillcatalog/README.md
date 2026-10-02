# Redactable skill catalog

The editable catalog lives in [catalog](catalog/). It was imported from
`sformisano/redactable-skills` at revision
`b710173f91f6c11c6c73f9a2b3fa18534077c7f5`
and reviewed against Redactable 0.14. Skills guide decisions; the
[README](../README.md) and [reference](../docs/reference.md) own API mechanics.

Catalog ID `redactable-skills`, all six skill IDs, stack `redactable`, and bundle
`redactable-skills` are unchanged. The stack still contains all six skills.
Sibling mentions no longer declare circular installation dependencies: each
skill stands alone and links to the product documentation it needs. Skill links
are absolute repository URLs so they remain usable after installation elsewhere.
They point at current documentation; use the consumer's locked revision when its
version differs from the catalog's 0.14 target.

## Installation

This repository is the only maintained catalog source. Use SkillCatalog 0.10.1
or later, which discovers `.skillcatalog/catalog` inside the library repository.
For a fresh profile, replace `/absolute/path/to/project` with the delivery directory:

```sh
skc catalog add https://github.com/sformisano/redactable.git
skc settings enable codex
skc profile create redactable-project /absolute/path/to/project \
  --entry bundle:redactable-skills:redactable-skills
skc deliver
skc deliver --check
```

Enable `claude-code` as well when that target is needed. For an existing profile,
select stack `redactable` or bundle `redactable-skills` from catalog
`redactable-skills`; both contain the six consumer skills.

## Replace the standalone source

The standalone repository is deleted. Its URL cannot serve updates or redirects.
Back up the SkillCatalog configuration and any local edits in its cached clone
before changing the registration. With SkillCatalog 0.10.1 or later, run:

```sh
skc catalog remove redactable-skills --force --keep-clone
skc catalog add https://github.com/sformisano/redactable.git
skc deliver
skc deliver --check
```

Removing the registration with `--force --keep-clone` preserves profile selections
and the old clone. Re-registering the same catalog ID connects those selections
to the library source. Delivery replaces the installed content. Check that both
enabled targets contain the six selected skills and no stale or edited managed
files. Retire the old clone after preserving any local edits; do not maintain it
as another catalog source. Update any setup scripts or profile manifests that
still name the standalone URL.

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
skill-example harness is retired.

Packaging checks do not validate judgment. Review changed guidance against code
and documentation, and exercise both a risky case and a valid counterexample.
For example, a bulk public declaration must be challenged, while an intentionally
omitted display-only field need not force a dual derive. Keep review results with
the change rather than treating a historical validation report as current proof.
