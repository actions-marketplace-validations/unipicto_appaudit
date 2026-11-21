"""appaudit PostToolUse hook: record tool calls in the engagement's evidence log.

Runs only while an engagement is open. Records every Bash and WebFetch call, and MCP calls
that carry a shell command or reach a host. Secrets are redacted before writing; the SHA-256
of the unredacted response is kept so a reviewer can match it against retained raw evidence.
Records are hash-chained (see scripts/verify_evidence.py). Never blocks a call.
"""
from __future__ import annotations

import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import appaudit_common as ac  # noqa: E402


def main() -> None:
    data = ac.read_input()
    if not data:
        return
    pdir = ac.project_dir(data)
    try:
        scope = ac.load_scope(pdir)
    except ac.ScopeError as exc:
        print(f"appaudit: evidence not logged: {exc}", file=sys.stderr)
        return
    if not ac.is_open(scope):
        return

    tool = data.get("tool_name", "")
    tool_input = data.get("tool_input") or {}
    hosts = ac.hosts_from_tool(tool, tool_input, data.get("cwd"))
    if tool.startswith("mcp__") and not hosts and not isinstance(tool_input.get("command"), str):
        return  # e.g. memory or document tools: not engagement activity

    response_text = ac.as_text(data.get("tool_response"))
    ac.append_evidence(pdir, {
        "ts": ac.iso(ac.utcnow()),
        "event": "tool_call",
        "engagement": scope.get("engagement"),
        "session": data.get("session_id"),
        "agent_type": data.get("agent_type"),
        "tool": tool,
        "tool_use_id": data.get("tool_use_id"),
        "hosts": sorted(hosts),
        "input": ac.redact(ac.clip(ac.as_text(tool_input))),
        "response_excerpt": ac.redact(ac.clip(response_text)),
        "response_sha256": hashlib.sha256(response_text.encode("utf-8", "replace")).hexdigest(),
    })


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001 - never block; surface the problem
        print(f"appaudit: evidence log error: {exc}", file=sys.stderr)
    sys.exit(0)
