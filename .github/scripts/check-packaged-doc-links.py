#!/usr/bin/env python3
"""Verify that every documentation link a published archive ships resolves
inside that same archive.

This reads the built `.crate` and never the source tree. A file that exists in
the checkout but is not packaged is a dead link for everyone who installs the
crate, and the checkout cannot tell you which files those are.

Four rules, in the order they are applied to each link:

1. Closure. For every markdown file in the archive, each relative link target
   must be an entry in that same archive, and each `#anchor` must match a
   heading extracted from the target file. Fenced code blocks are skipped.

2. Exempt destinations, not files. A link is exempt when its destination is a
   repository path that no package include pattern can ever match --
   `.github/scripts/*.sh` from the contributor guide is correct on GitHub and
   never in the archive. The exempt set is the committed constant
   EXEMPT_DESTINATIONS below and is deliberately NOT read from the manifest's
   `include` list: reading it from the manifest would mean that dropping
   `docs/**/*.md` from `include` also exempts every link that points into
   `docs/`, which is the regression this checker exists to catch. Exempting
   whole *files* is the same hole one level up -- it unchecks their in-archive
   links too, so an archive can ship `CONTRIBUTING.md` pointing at a
   `docs/reference.md` it no longer contains and stay green.

3. No absolute-URL escape, with one carve-out. A packaged markdown file that
   links by absolute URL to a path which *is* in the archive fails. Otherwise
   the cheapest way to clear a red run is to rewrite the relative links to
   `blob/main/...` URLs, which ships a README whose reference no offline reader
   can reach. The carve-out is for a URL pinned to a revision other than the one
   being packaged: `CONTRIBUTING.md` cites a historical README by permalink on
   purpose. Concretely: fail on `blob/main`, on `blob/<version being packaged>`
   (with or without a leading `v`) and on a bare `blob/HEAD`; ignore any other
   ref.

4. A counted inventory, not a floor. One line per distinct
   `(source file, link destination, occurrences)` triple resolved inside the
   archive, sorted, with no line numbers so it survives reflow. A floor fails in
   both directions: lowering it in the same commit clears an archive that ships
   no `docs/` at all, and deleting one redundant duplicate link goes red with no
   exemption. A pair-keyed set without counts fails in one direction: five real
   duplicate links can be deleted with the committed file byte-identical.

Usage:

    check-packaged-doc-links.py --archive target/package/redactable-0.13.0.crate \\
        --package-root redactable-0.13.0 --version 0.13.0 \\
        --inventory .github/packaged-doc-links/redactable.txt

Add `--regenerate` to rewrite the inventory file from the archive instead of
comparing against it. Regenerating is a reviewed change: the diff is the list of
links the published artifact gained, lost, or now repeats a different number of
times.
"""

from __future__ import annotations

import argparse
import posixpath
import re
import sys
import tarfile
import urllib.parse
from collections import Counter
from dataclasses import dataclass

# Repository paths that no package include pattern can ever match. A link whose
# destination resolves into one of these is correct on GitHub and is not
# expected in the archive. Adding an entry here is a reviewed change; see rule 2
# in the module docstring for why this list is a constant and not the manifest's
# `include` list.
EXEMPT_DESTINATIONS = (
    ".github/",
    ".githooks/",
    "cargo-fixtures/",
    "test-fixtures/",
    "redactable-derive/",
    "tests/",
    ".gitignore",
    "deny.toml",
    "rustfmt.toml",
)

# The repository this crate is published from. Rule 3 only fires for URLs into
# this repository; a link to some other project's file on GitHub is an ordinary
# outbound link. Hardcoded rather than read from the packaged manifest for the
# same reason EXEMPT_DESTINATIONS is: a check that reads its own scope out of an
# editable field can be switched off by editing that field.
REPOSITORY_URL_PREFIXES = (
    "https://github.com/sformisano/redactable/",
    "http://github.com/sformisano/redactable/",
)

MARKDOWN_SUFFIX = ".md"

FENCE_RE = re.compile(r"^\s{0,3}(`{3,}|~{3,})")
ATX_HEADING_RE = re.compile(r"^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$")
SETEXT_UNDERLINE_RE = re.compile(r"^\s{0,3}(=+|-+)\s*$")
INLINE_LINK_RE = re.compile(r"\[(?:[^\[\]]|\\.)*\]\(\s*(<[^>]*>|[^\s()]*)")
REFERENCE_DEFINITION_RE = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*(<[^>]*>|\S+)")
SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:")
BLOB_RE = re.compile(r"^blob/([^/]+)/(.+)$")


@dataclass(frozen=True)
class Link:
    source: str
    line: int
    destination: str


@dataclass(frozen=True)
class Failure:
    source: str
    line: int
    destination: str
    reason: str

    def render(self) -> str:
        return f"{self.source}:{self.line}: {self.destination}: {self.reason}"


def read_archive(archive_path: str, package_root: str) -> dict[str, bytes | None]:
    """Return every archive entry keyed by its path below the package root.

    The value is the file's bytes for markdown, and None for everything else:
    closure only needs to know that a non-markdown entry exists.
    """
    entries: dict[str, bytes | None] = {}
    prefix = package_root.rstrip("/") + "/"
    with tarfile.open(archive_path, "r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            name = member.name
            if not name.startswith(prefix):
                raise SystemExit(
                    f"{archive_path}: entry {name!r} is outside {prefix!r}"
                )
            relative = name[len(prefix) :]
            if relative.endswith(MARKDOWN_SUFFIX):
                handle = tar.extractfile(member)
                entries[relative] = handle.read() if handle is not None else b""
            else:
                entries[relative] = None
    return entries


def strip_fenced_code(lines: list[str]) -> list[str | None]:
    """Blank out lines inside fenced code blocks, keeping line numbering."""
    result: list[str | None] = []
    fence_char: str | None = None
    fence_length = 0
    for line in lines:
        match = FENCE_RE.match(line)
        if match:
            token = match.group(1)
            if fence_char is None:
                fence_char = token[0]
                fence_length = len(token)
                result.append(None)
                continue
            if token[0] == fence_char and len(token) >= fence_length:
                fence_char = None
                result.append(None)
                continue
        result.append(None if fence_char is not None else line)
    return result


def slugify(heading: str) -> str:
    """GitHub's heading slug: drop HTML, drop punctuation, lowercase, dash spaces."""
    text = re.sub(r"<[^>]*>", "", heading)
    text = text.replace("`", "")
    # Strip markdown emphasis and link syntax, keeping the visible text.
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = text.strip().lower()
    text = re.sub(r"[^\w\- ]", "", text, flags=re.UNICODE)
    return text.replace(" ", "-")


def extract_anchors(content: str) -> set[str]:
    lines = strip_fenced_code(content.split("\n"))
    anchors: set[str] = set()
    counts: Counter[str] = Counter()
    previous: str | None = None

    def add(raw: str) -> None:
        slug = slugify(raw)
        if not slug:
            return
        seen = counts[slug]
        counts[slug] = seen + 1
        anchors.add(slug if seen == 0 else f"{slug}-{seen}")

    for line in lines:
        if line is None:
            previous = None
            continue
        match = ATX_HEADING_RE.match(line)
        if match:
            add(match.group(2))
            previous = None
            continue
        if previous and SETEXT_UNDERLINE_RE.match(line) and previous.strip():
            add(previous)
            previous = None
            continue
        previous = line
    return anchors


def extract_links(source: str, content: str) -> list[Link]:
    links: list[Link] = []
    for number, line in enumerate(strip_fenced_code(content.split("\n")), start=1):
        if line is None:
            continue
        destinations = [m.group(1) for m in INLINE_LINK_RE.finditer(line)]
        definition = REFERENCE_DEFINITION_RE.match(line)
        if definition:
            destinations.append(definition.group(1))
        for raw in destinations:
            destination = raw.strip()
            if destination.startswith("<") and destination.endswith(">"):
                destination = destination[1:-1].strip()
            if destination:
                links.append(Link(source, number, destination))
    return links


def is_exempt(path: str) -> bool:
    return any(
        path == pattern.rstrip("/") or path.startswith(pattern)
        for pattern in EXEMPT_DESTINATIONS
    )


def resolve(source: str, path: str) -> str | None:
    """Resolve a link path against its source file. None if it escapes the archive."""
    base = posixpath.dirname(source)
    joined = posixpath.normpath(posixpath.join(base, path)) if base else posixpath.normpath(path)
    if joined == ".." or joined.startswith("../"):
        return None
    return joined


def blocked_refs(version: str) -> set[str]:
    return {"main", "HEAD", version, f"v{version}"}


def check_absolute(link: Link, entries: dict[str, bytes | None], version: str) -> Failure | None:
    for prefix in REPOSITORY_URL_PREFIXES:
        if link.destination.startswith(prefix):
            remainder = link.destination[len(prefix) :]
            break
    else:
        return None
    remainder = remainder.split("#", 1)[0].split("?", 1)[0]
    match = BLOB_RE.match(remainder)
    if not match:
        return None
    ref, path = match.group(1), urllib.parse.unquote(match.group(2))
    if ref not in blocked_refs(version):
        # A permalink to some other revision is a deliberate citation of
        # history, not a way around closure.
        return None
    if path not in entries:
        return None
    return Failure(
        link.source,
        link.line,
        link.destination,
        f"in-archive target {path!r} linked by absolute URL at ref {ref!r}; "
        "link it relatively so the archive resolves offline",
    )


def check_relative(
    link: Link, entries: dict[str, bytes | None], anchors: dict[str, set[str]]
) -> tuple[Failure | None, tuple[str, str] | None]:
    """Apply closure. Returns (failure, verified triple key)."""
    raw_path, _, raw_anchor = link.destination.partition("#")
    anchor = urllib.parse.unquote(raw_anchor)
    if raw_path == "":
        target = link.source
    else:
        resolved = resolve(link.source, urllib.parse.unquote(raw_path))
        if resolved is None:
            return (
                Failure(
                    link.source,
                    link.line,
                    link.destination,
                    "link escapes the package root",
                ),
                None,
            )
        if is_exempt(resolved):
            return None, None
        target = resolved
        if target not in entries:
            return (
                Failure(
                    link.source,
                    link.line,
                    link.destination,
                    f"target {target!r} is not in the archive",
                ),
                None,
            )
    if anchor:
        if target not in anchors:
            return (
                Failure(
                    link.source,
                    link.line,
                    link.destination,
                    f"target {target!r} is not markdown, so it has no headings",
                ),
                None,
            )
        if anchor.lower() not in anchors[target]:
            return (
                Failure(
                    link.source,
                    link.line,
                    link.destination,
                    f"no heading in {target!r} produces anchor {anchor!r}",
                ),
                None,
            )
    return None, (link.source, link.destination)


def format_inventory(counts: Counter[tuple[str, str]]) -> list[str]:
    return [
        f"{source}\t{destination}\t{count}"
        for (source, destination), count in sorted(counts.items())
    ]


def parse_inventory(text: str) -> Counter[tuple[str, str]]:
    counts: Counter[tuple[str, str]] = Counter()
    for number, line in enumerate(text.split("\n"), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 3:
            raise SystemExit(
                f"inventory line {number} is not <source>TAB<destination>TAB<count>: {line!r}"
            )
        counts[(parts[0], parts[1])] = int(parts[2])
    return counts


INVENTORY_HEADER = (
    "# Documentation links verified inside the published archive.\n"
    "# One line per (source file, link destination, occurrences), tab separated,\n"
    "# sorted, generated from the .crate by\n"
    "# .github/scripts/check-packaged-doc-links.py --regenerate.\n"
    "# Counts are load-bearing: deleting one of several identical links is a real\n"
    "# change to the shipped document and must show up as a diff here.\n"
)


def diff_inventory(
    committed: Counter[tuple[str, str]], measured: Counter[tuple[str, str]]
) -> list[str]:
    lines: list[str] = []
    for key in sorted(set(committed) | set(measured)):
        was, now = committed.get(key, 0), measured.get(key, 0)
        if was == now:
            continue
        source, destination = key
        if was == 0:
            lines.append(f"added    {source}\t{destination}\t{now}")
        elif now == 0:
            lines.append(f"removed  {source}\t{destination}\t{was}")
        else:
            lines.append(f"changed  {source}\t{destination}\t{was} -> {now}")
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--package-root", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--regenerate", action="store_true")
    args = parser.parse_args()

    entries = read_archive(args.archive, args.package_root)
    markdown = {
        path: content.decode("utf-8")
        for path, content in sorted(entries.items())
        if content is not None
    }
    anchors = {path: extract_anchors(text) for path, text in markdown.items()}

    failures: list[Failure] = []
    verified: Counter[tuple[str, str]] = Counter()

    for path, text in markdown.items():
        for link in extract_links(path, text):
            if SCHEME_RE.match(link.destination):
                failure = check_absolute(link, entries, args.version)
                if failure is not None:
                    failures.append(failure)
                continue
            failure, key = check_relative(link, entries, anchors)
            if failure is not None:
                failures.append(failure)
            elif key is not None:
                verified[key] += 1

    if args.regenerate:
        with open(args.inventory, "w", encoding="utf-8") as handle:
            handle.write(INVENTORY_HEADER)
            for line in format_inventory(verified):
                handle.write(line + "\n")
        total = sum(verified.values())
        print(
            f"{args.archive}: wrote {args.inventory} "
            f"({len(verified)} triples, {total} verified link occurrences)"
        )
        if failures:
            print(
                f"{args.archive}: {len(failures)} unresolved link(s) remain:",
                file=sys.stderr,
            )
            for failure in failures:
                print(f"  {failure.render()}", file=sys.stderr)
            return 1
        return 0

    try:
        with open(args.inventory, encoding="utf-8") as handle:
            committed = parse_inventory(handle.read())
    except FileNotFoundError:
        print(
            f"{args.inventory} does not exist; generate it with --regenerate",
            file=sys.stderr,
        )
        return 1

    exit_code = 0
    if failures:
        print(
            f"{args.archive}: {len(failures)} documentation link(s) do not resolve "
            "inside the archive:",
            file=sys.stderr,
        )
        for failure in failures:
            print(f"  {failure.render()}", file=sys.stderr)
        exit_code = 1

    differences = diff_inventory(committed, verified)
    if differences:
        print(
            f"{args.archive}: packaged link inventory differs from {args.inventory}:",
            file=sys.stderr,
        )
        for line in differences:
            print(f"  {line}", file=sys.stderr)
        print(
            "  regenerate with --regenerate and review the diff",
            file=sys.stderr,
        )
        exit_code = 1

    if exit_code == 0:
        total = sum(verified.values())
        print(
            f"{args.archive}: {total} documentation link occurrence(s) across "
            f"{len(verified)} distinct (file, destination) pairs in "
            f"{len(markdown)} packaged markdown file(s) resolve inside the archive, "
            f"matching {args.inventory}"
        )
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
