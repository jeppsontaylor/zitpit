#!/usr/bin/env python3

import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parent.parent
PAPER = ROOT / "paper" / "main.tex"
DRAFT = ROOT / "papers" / "publication-draft.md"
THESIS = "consumer-side software admission control layer for agentic development"
SECTION_MAP = {
    "Introduction": "1. Introduction",
    "Why Admission Control Matters": "2. Why Admission Control Matters",
    "Current Proof Boundary": "3. Current Proof Boundary",
    "Threat Model and Definitions": "4. Threat Model",
    "Architecture and Policy": "5. Architecture and Policy",
    "Preliminary Evaluation": "6. Preliminary Evaluation",
    "Related Work": "7. Related Work",
    "Implications": "8. Implications",
    "Limitations and Future Work": "9. Limitations and Future Work",
    "Conclusion": "10. Conclusion",
}


def fail(message: str) -> None:
    print(f"publication sync check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    paper_text = PAPER.read_text()
    draft_text = DRAFT.read_text()

    if THESIS not in paper_text.lower():
        fail("canonical thesis sentence is missing from paper/main.tex")
    if THESIS not in draft_text.lower():
        fail("canonical thesis sentence is missing from papers/publication-draft.md")

    paper_sections = set(re.findall(r"\\section\{([^}]+)\}", paper_text))
    for paper_section, draft_heading in SECTION_MAP.items():
        if paper_section not in paper_sections:
            fail(f"paper section missing: {paper_section}")
        if draft_heading not in draft_text:
            fail(f"publication draft heading missing: {draft_heading}")

    print("publication sync check passed")


if __name__ == "__main__":
    main()
