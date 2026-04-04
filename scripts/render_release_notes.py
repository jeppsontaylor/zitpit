#!/usr/bin/env python3

from __future__ import annotations

import argparse
import pathlib
import re
import sys


def extract_section(text: str, version: str) -> str:
    heading = re.compile(r"^## \[(?P<name>[^\]]+)\]\s*$", re.MULTILINE)
    matches = list(heading.finditer(text))
    fallback = None
    for index, match in enumerate(matches):
        name = match.group("name")
        if name == "Unreleased" and fallback is None:
            start = match.end()
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            body = text[start:end].strip()
            fallback = f"## [{version}]\n\n{body}\n"
        if name != version:
            continue
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        body = text[start:end].strip()
        return f"## [{version}]\n\n{body}\n"
    if fallback is not None:
        return fallback
    raise ValueError(f"version section [{version}] not found in changelog")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("version", help="release version without the leading v")
    parser.add_argument(
        "--changelog",
        default="CHANGELOG.md",
        help="path to changelog (default: CHANGELOG.md)",
    )
    args = parser.parse_args()

    changelog_path = pathlib.Path(args.changelog)
    text = changelog_path.read_text(encoding="utf-8")
    try:
        notes = extract_section(text, args.version)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    sys.stdout.write(notes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
