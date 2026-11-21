"""appaudit SessionStart hook: tell Claude whether an engagement is open in this project."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import appaudit_common as ac  # noqa: E402


def context(text: str) -> None:
    ac.emit({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": text}})


def fmt(items) -> str:
    items = [str(i) for i in (items or [])]
    return ", ".join(items) if items else "none"


def main() -> None:
    data = ac.read_input()
    pdir = ac.project_dir(data)
    try:
        scope = ac.load_scope(pdir)
    except ac.ScopeError as exc:
        context(f"appaudit: the engagement scope file cannot be read ({exc}). The scope guard blocks "
                "network-reaching tool calls until it is fixed with /appaudit:scope.")
        return
    if not ac.is_open(scope):
        return
    auth = scope.get("authorization") or {}
    window = scope.get("window") or {}
    ins = scope.get("in_scope") or {}
    outs = scope.get("out_of_scope") or {}
    prof = scope.get("jurisdiction_profile") or {}
    if prof:
        regions = sorted({str(x) for k in ("established_in", "markets", "data_subject_regions", "hosting_locations")
                          for x in (prof.get(k) or [])})
        juris = (f"Jurisdictions: {fmt(regions)}; roles {fmt(prof.get('roles'))}; "
                 f"counsel-confirmed for testing {fmt(prof.get('counsel_confirmed'))}\n")
    else:
        juris = "Jurisdictions: no profile recorded, so regulatory triggers will be reported as not assessed\n"
    context(
        "An appaudit security engagement is open in this project.\n"
        f"Engagement: {scope.get('engagement', 'unnamed')}\n"
        f"Authorization: {auth.get('basis', 'not recorded')} ({auth.get('reference', 'no reference')})\n"
        f"Mode: {scope.get('mode', 'static')} (static = no contact with targets)\n"
        f"Testing window: {window.get('start', 'not set')} to {window.get('end') or 'open-ended'}\n"
        f"In scope: hosts {fmt(ins.get('hosts'))}; ranges {fmt(ins.get('cidrs'))}\n"
        f"Out of scope: hosts {fmt(outs.get('hosts'))}; ranges {fmt(outs.get('cidrs'))}\n"
        f"Rate cap: {scope.get('rate_limit_rps', 'not set')} requests/s. Prohibited: {fmt(scope.get('prohibited'))}\n"
        f"{juris}"
        "The appaudit scope guard blocks tool calls that contact any other host, and Bash, WebFetch and "
        "network-reaching MCP calls are recorded in .appaudit/evidence/evidence.jsonl."
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        print(f"appaudit session-start error: {exc}", file=sys.stderr)
    sys.exit(0)
