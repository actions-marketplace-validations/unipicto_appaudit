"""Verify the hash chain of an appaudit evidence log.

Usage:  python3 verify_evidence.py [path/to/evidence.jsonl] [--expect-head SHA256]
Default path: ./.appaudit/evidence/evidence.jsonl
Prints a JSON result; exit code 0 if the chain verifies, 1 otherwise.

The chain shows that no record was changed, removed or reordered after it was written. Someone
who can write the file could still rebuild the whole chain, so note the head hash somewhere the
assessor cannot change (send it to the client when the engagement closes) and check it later
with --expect-head.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "hooks"))

import appaudit_common as ac  # noqa: E402


def main() -> int:
    args = sys.argv[1:]
    expect = None
    if "--expect-head" in args:
        i = args.index("--expect-head")
        expect = args[i + 1].strip().lower() if i + 1 < len(args) else ""
        del args[i:i + 2]
    path = Path(args[0]) if args else Path.cwd() / ac.EVIDENCE_REL
    result = ac.verify_log(path)
    if expect is not None:
        result["expected_head"] = expect
        result["head_matches"] = bool(result.get("head_sha256")) and result["head_sha256"] == expect
        if not result["head_matches"]:
            result["verified"] = False
            result["first_error"] = result.get("first_error") or "head hash differs from the expected (anchored) value"
    print(json.dumps(result, indent=2))
    return 0 if result["verified"] else 1


if __name__ == "__main__":
    sys.exit(main())
