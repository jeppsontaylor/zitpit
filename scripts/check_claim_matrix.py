#!/usr/bin/env python3

import json
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parent.parent
CLAIM_MATRIX = ROOT / "docs" / "claim-matrix.yaml"
ALLOWED_STATUSES = {"Implemented", "Partial", "Planned", "Unsupported"}


def fail(message: str) -> None:
    print(f"claim matrix check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    try:
        data = json.loads(CLAIM_MATRIX.read_text())
    except FileNotFoundError:
        fail("docs/claim-matrix.yaml is missing")
    except json.JSONDecodeError as exc:
        fail(f"docs/claim-matrix.yaml is not valid JSON-compatible YAML: {exc}")

    if data.get("canonical_description") != "consumer-side software admission control layer for agentic development":
        fail("canonical description drifted")

    claims = data.get("claims")
    if not isinstance(claims, list) or not claims:
        fail("claims list is missing or empty")

    for claim in claims:
        claim_id = claim.get("id", "<missing>")
        status = claim.get("status")
        if status not in ALLOWED_STATUSES:
            fail(f"{claim_id}: invalid status {status!r}")
        for field in ["supported_claim", "public_evidence", "code_paths", "demo_command", "not_yet_proven"]:
            if field not in claim:
                fail(f"{claim_id}: missing required field {field}")
        for evidence in claim["public_evidence"]:
            path = ROOT / evidence["path"]
            if not path.exists():
                fail(f"{claim_id}: evidence path does not exist: {evidence['path']}")
        for code_path in claim["code_paths"]:
            path = ROOT / code_path
            if not path.exists():
                fail(f"{claim_id}: code path does not exist: {code_path}")

    print("claim matrix check passed")


if __name__ == "__main__":
    main()
