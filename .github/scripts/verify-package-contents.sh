#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

version="$({ cargo metadata --no-deps --format-version 1; } | python3 -c '
import json, sys
packages = json.load(sys.stdin)["packages"]
versions = {p["version"] for p in packages if p["name"] in {"redactable", "redactable-derive"}}
if len(versions) != 1:
    raise SystemExit(f"workspace crates do not share one version: {sorted(versions)}")
print(versions.pop())
')"

allow_dirty_flag=""
if [[ "${PACKAGE_ALLOW_DIRTY:-0}" == "1" ]]; then
    allow_dirty_flag="--allow-dirty"
fi

for crate in redactable-derive redactable; do
    package_root="${crate}-${version}"
    archive="target/package/${package_root}.crate"
    if [[ "$crate" == "redactable" ]]; then
        # The runtime pins the exact derive version. Before either crate is
        # uploaded, resolve that pin to the reviewed local derive package.
        cargo package --locked -p "$crate" $allow_dirty_flag \
            --config 'patch.crates-io.redactable-derive.path="redactable-derive"'
        package_list="$(cargo package --locked --list -p "$crate" $allow_dirty_flag \
            --config 'patch.crates-io.redactable-derive.path="redactable-derive"')"
    else
        cargo package --locked -p "$crate" $allow_dirty_flag
        package_list="$(cargo package --locked --list -p "$crate" $allow_dirty_flag)"
    fi
    if ! grep -Fxq "LICENSE.md" <<<"$package_list"; then
        echo "$crate package list does not contain LICENSE.md" >&2
        exit 1
    fi

    if ! tar -tzf "$archive" | grep -Fx "${package_root}/LICENSE.md" >/dev/null; then
        echo "$archive does not contain ${package_root}/LICENSE.md" >&2
        exit 1
    fi

    tar -xOzf "$archive" "${package_root}/LICENSE.md" | cmp - LICENSE.md

    # Every documentation link the archive ships must resolve inside the
    # archive. This reads the .crate rather than the checkout: a file that is
    # present here and not packaged is a dead link for everyone who installs
    # the crate.
    python3 .github/scripts/check-packaged-doc-links.py \
        --archive "$archive" \
        --package-root "$package_root" \
        --version "$version" \
        --inventory ".github/packaged-doc-links/${crate}.txt"
done
