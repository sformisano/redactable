#!/usr/bin/env bash
# After strip-cursor-attribution.sh, remote tags still point at OLD commits,
# so GitHub keeps those objects and can still show cursoragent as contributor.
# This script deletes remote tags and re-creates them on the rewritten main.
# Run from repo root. Then refresh GitHub contributors (see README or below).

set -e
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "Not inside a git repo. Run from repo root." >&2
  exit 1
fi

# New SHAs on rewritten main, first (oldest) to last (newest)
# Order must match the original tag order: v0.1.0 = 1st commit, v0.5.3 = 16th
NEW_TAG_SHA=(
  "a8f7e43"  # v0.1.0
  "59a662f"  # v0.1.1
  "6cb21d5"  # v0.1.2
  "ed2264a"  # v0.2.0
  "7c6241b"  # v0.2.1
  "f8a497c"  # v0.2.2
  "b285454"  # v0.2.3
  "096a46f"  # v0.3.0
  "cd7476b"  # v0.3.1
  "7aae59a"  # v0.3.2
  "52ec069"  # v0.4.1
  "9abf1a0"  # v0.5.0
  "e29d5ba"  # v0.5.1
  "414707d"  # v0.5.2
  "8d931a3"  # v0.5.3
)
TAGS=(v0.1.0 v0.1.1 v0.1.2 v0.2.0 v0.2.1 v0.2.2 v0.2.3 v0.3.0 v0.3.1 v0.3.2 v0.4.1 v0.5.0 v0.5.1 v0.5.2 v0.5.3)

echo "Deleting old remote tags (they point at pre-rewrite commits)..."
for t in "${TAGS[@]}"; do
  git push origin --delete "$t" 2>/dev/null || true
done

echo "Creating tags on rewritten commits and pushing..."
for i in "${!TAGS[@]}"; do
  git tag -f "${TAGS[$i]}" "${NEW_TAG_SHA[$i]}"
done
git push origin --tags --force

echo ""
echo "Done. Next: refresh GitHub contributor list by renaming the default branch."
echo "On GitHub: Repository -> branches -> rename 'main' to 'main1' -> rename back to 'main'."
