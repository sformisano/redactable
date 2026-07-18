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

if [[ -n "${GITHUB_SHA:-}" ]] && [[ "$(git rev-parse HEAD)" != "$GITHUB_SHA" ]]; then
    echo "checked-out commit does not match GITHUB_SHA" >&2
    exit 1
fi

if [[ "${GITHUB_REF_TYPE:-}" == "tag" ]] && [[ "${GITHUB_REF_NAME}" != "v${version}" ]]; then
    echo "tag ${GITHUB_REF_NAME} does not match workspace version v${version}" >&2
    exit 1
fi

source_commit="$(git rev-parse HEAD)"
if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
    echo "release checkout must be clean before packaging" >&2
    exit 1
fi

# Assemble and inspect both archives before the first upload. This also makes
# the script safe to invoke outside the workflow without skipping preflight.
"$repo_root/.github/scripts/verify-package-contents.sh"

# `cargo publish` packages from the working tree again. Pinning the commit and
# requiring a clean tree before and after prepackaging proves that upload uses
# the same reviewed source, manifests, README, and license as the archives just
# compiled and inspected.
assert_unchanged_source() {
    if [[ "$(git rev-parse HEAD)" != "$source_commit" ]] || \
        [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
        echo "release source changed after package validation" >&2
        exit 1
    fi
}

assert_unchanged_source

crate_version_status() {
    local crate="$1"
    curl \
        --silent \
        --show-error \
        --output /dev/null \
        --write-out '%{http_code}' \
        --user-agent 'redactable-release-workflow' \
        "https://crates.io/api/v1/crates/${crate}/${version}"
}

crate_version_body() {
    local crate="$1"
    curl \
        --silent \
        --show-error \
        --user-agent 'redactable-release-workflow' \
        "https://crates.io/api/v1/crates/${crate}/${version}"
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# A version number is not an identity. crates.io is immutable and `redactable`
# pins `redactable-derive` with `=`, so accepting an existing version on its
# number alone lets a retry publish the runtime against a derive built from
# different source - permanently, with no way to correct it. A yanked version
# also answers 200 and must never be treated as a satisfied dependency.
#
# Only an exact checksum match against the archive we just packaged and
# inspected proves the registry already holds *this* reviewed source.
assert_published_matches_local() {
    local crate="$1"
    local archive="target/package/${crate}-${version}.crate"
    local body remote_checksum yanked local_checksum

    if [[ ! -f "$archive" ]]; then
        echo "cannot verify published ${crate} ${version}: missing local archive ${archive}" >&2
        exit 1
    fi

    body="$(crate_version_body "$crate")"
    remote_checksum="$(printf '%s' "$body" | python3 -c '
import json, sys
print(json.load(sys.stdin)["version"]["checksum"])
')" || { echo "could not read checksum for ${crate} ${version} from crates.io" >&2; exit 1; }
    yanked="$(printf '%s' "$body" | python3 -c '
import json, sys
print(str(json.load(sys.stdin)["version"]["yanked"]).lower())
')" || { echo "could not read yanked flag for ${crate} ${version} from crates.io" >&2; exit 1; }

    if [[ "$yanked" == "true" ]]; then
        echo "${crate} ${version} is yanked on crates.io; refusing to depend on or skip it." >&2
        echo "Publish a new version instead of reusing a yanked one." >&2
        exit 1
    fi

    local_checksum="$(sha256_of "$archive")"
    if [[ "$remote_checksum" != "$local_checksum" ]]; then
        echo "${crate} ${version} already exists on crates.io but was built from DIFFERENT source." >&2
        echo "  crates.io checksum: ${remote_checksum}" >&2
        echo "  local archive:      ${local_checksum} (${archive})" >&2
        echo "Publishing against it would permanently bind this release to unreviewed code." >&2
        echo "Bump the version; the existing one cannot be corrected." >&2
        exit 1
    fi
}

# Presence only. Deliberately does NOT check identity: `wait_until_visible` uses
# this to confirm our own fresh upload landed, where an identity check would be
# both redundant and able to fail a release that already succeeded.
# 0 = present, 1 = absent (404), 2 = transport/unknown status, caller must abort.
exact_version_exists() {
    local crate="$1"
    local status
    status="$(crate_version_status "$crate")"
    case "$status" in
        200) return 0 ;;
        404) return 1 ;;
        *)
            echo "crates.io returned HTTP ${status} for ${crate} ${version}" >&2
            return 2
            ;;
    esac
}

wait_until_visible() {
    local crate="$1"
    local attempts="${2:-40}"
    local delay_seconds="${3:-15}"
    local status

    for ((attempt = 1; attempt <= attempts; attempt++)); do
        if exact_version_exists "$crate"; then
            return 0
        else
            status=$?
        fi
        if [[ "$status" -eq 2 ]]; then
            exit 1
        fi
        if [[ "$attempt" -lt "$attempts" ]]; then
            sleep "$delay_seconds"
        fi
    done

    echo "timed out waiting for ${crate} ${version} on crates.io" >&2
    return 1
}

publish_if_missing() {
    local crate="$1"
    local publish_status
    local status

    assert_unchanged_source

    # Skipping is only safe once the registry copy is proven to be this exact
    # reviewed source. `assert_published_matches_local` exits on a mismatch or a
    # yanked version rather than letting the run continue.
    if exact_version_exists "$crate"; then
        assert_published_matches_local "$crate"
        echo "${crate} ${version} is already published from this exact source"
        return 0
    else
        status=$?
    fi
    if [[ "$status" -eq 2 ]]; then
        exit 1
    fi

    set +e
    cargo publish --locked -p "$crate"
    publish_status=$?
    set -e
    if [[ "$publish_status" -eq 0 ]]; then
        return 0
    fi

    # A concurrent or retried run may have completed the exact upload while this
    # command was running. `wait_until_visible` only proves the version NUMBER is
    # present - a concurrent uploader could have published different source, or a
    # yanked build - so identity must be re-proven here exactly as on the
    # initial-existence path. Without this, a publish race could bind `redactable`
    # to an unreviewed `redactable-derive`, permanently.
    if wait_until_visible "$crate" 20 15; then
        assert_published_matches_local "$crate"
        echo "${crate} ${version} became visible after the publish attempt (checksum-verified)"
        return 0
    fi

    return "$publish_status"
}

publish_if_missing redactable-derive
wait_until_visible redactable-derive
publish_if_missing redactable
wait_until_visible redactable
