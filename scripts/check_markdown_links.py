#!/usr/bin/env python3

import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parent.parent
LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
SKIP_PREFIXES = ("http://", "https://", "mailto:", "#")


def fail(message: str) -> None:
    print(f"markdown link check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def iter_markdown_files():
    for path in ROOT.rglob("*.md"):
        if "target" in path.parts or "dist" in path.parts:
            continue
        yield path


def main() -> None:
    for markdown_file in iter_markdown_files():
        text = markdown_file.read_text()
        for raw_target in LINK_RE.findall(text):
            target = raw_target.split("#", 1)[0].strip()
            if not target or target.startswith(SKIP_PREFIXES):
                continue
            if target.startswith("<") and target.endswith(">"):
                target = target[1:-1]
            resolved = (markdown_file.parent / target).resolve()
            try:
                resolved.relative_to(ROOT.resolve())
            except ValueError:
                fail(f"{markdown_file}: link escapes repository root: {raw_target}")
            if not resolved.exists():
                fail(f"{markdown_file}: missing local link target {raw_target}")

    print("markdown link check passed")


if __name__ == "__main__":
    main()
