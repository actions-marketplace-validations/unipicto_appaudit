"""appaudit PreToolUse hook: enforce the engagement scope.

- No open engagement (.appaudit/scope.json missing or status != "open"): does nothing,
  except that changes to existing engagement files still need the user's approval.
- Open engagement: denies any tool call that would contact a host outside in_scope and
  support_hosts, any target outside the testing window, and any target in static mode.
- Open engagement, uncertain cases: asks the user when a command names a possible out-of-scope
  host in the arguments of a program the guard does not know, reads its targets from a file the
  guard cannot read, uses a host alias, or builds what it runs at run time.
- No open engagement: asks before a scanning or attack tool runs (option scanner_gate: ask,
  deny or off), so that such tools are not started without a recorded scope.
- Never returns "allow": a call it lets through still goes through the normal permission flow.
- Fails closed: if the scope file is unreadable or the guard itself errors during an open
  (or unknown) engagement, network-reaching calls are denied.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import appaudit_common as ac  # noqa: E402


def decide(kind: str, reason: str) -> None:
    ac.emit({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": kind, "permissionDecisionReason": reason}})


def log(pdir, scope, data, event, hosts, reason):
    if not ac.is_open(scope):
        return
    try:
        ac.append_evidence(pdir, {
            "ts": ac.iso(ac.utcnow()),
            "event": event,
            "engagement": scope.get("engagement"),
            "session": data.get("session_id"),
            "agent_type": data.get("agent_type"),
            "tool": data.get("tool_name"),
            "tool_use_id": data.get("tool_use_id"),
            "hosts": sorted(hosts),
            "input": ac.redact(ac.clip(ac.as_text(data.get("tool_input")))),
            "reason": reason,
        })
    except Exception as exc:  # noqa: BLE001 - logging must not change the decision
        print(f"appaudit: could not write evidence log: {exc}", file=sys.stderr)


def main() -> None:
    data = ac.read_input()
    if not data:
        return
    pdir = ac.project_dir(data)
    tool = data.get("tool_name", "")
    tool_input = data.get("tool_input") or {}
    cwd = data.get("cwd")

    scope_exists = (pdir / ac.SCOPE_REL).exists()
    try:
        scope = ac.load_scope(pdir)
        scope_error = None
    except ac.ScopeError as exc:
        scope, scope_error = None, str(exc)

    # 1. Engagement files: changes always need the user's approval.
    if scope_exists:
        target = ac.protected_target(tool, tool_input)
        if target:
            reason = (f"appaudit: this call would change {target}. Scope and evidence changes need "
                      "the user's explicit approval; approve only if you asked for this change.")
            log(pdir, scope, data, "approval_requested", set(), reason)
            decide("ask", reason)
            return

    hosts = ac.hosts_from_tool(tool, tool_input, cwd)

    # 2. Broken scope file: fail closed for anything that reaches a host.
    if scope_error:
        if hosts:
            decide("deny", f"appaudit scope guard: {scope_error}. Network-reaching calls are blocked "
                           "until the user fixes the file (run /appaudit:scope).")
        return

    command = tool_input.get("command") if isinstance(tool_input.get("command"), str) else ""
    shell_like = bool(command) and tool not in ("Write", "Edit", "MultiEdit", "NotebookEdit")

    # 3. No open engagement: only the scanner gate applies.
    if not ac.is_open(scope):
        gate = (os.environ.get("CLAUDE_PLUGIN_OPTION_SCANNER_GATE") or "ask").strip().lower()
        scanner = ac.scanner_in(command) if shell_like and gate not in ("off", "none", "false", "0") else None
        if scanner:
            decide("deny" if gate == "deny" else "ask",
                   f"appaudit: '{scanner}' is a scanning or attack tool and no appaudit engagement is open in this "
                   "project. Record the owner's permission and the scope first with /appaudit:scope. Approve only "
                   "if you own the target or have the owner's written permission.")
        return

    soft_hosts, soft_reasons = (ac.soft_signals(command, cwd) if shell_like and not ac.is_trusted_invocation(command)
                                else (set(), []))
    if not hosts and not soft_hosts and not soft_reasons:
        return

    now = ac.utcnow()
    denied = []
    for host in sorted(hosts):
        ok, why = ac.classify(host, scope, now)
        if not ok:
            denied.append(why)
    if denied:
        reason = ("appaudit scope guard blocked this call: " + "; ".join(denied) + ". "
                  "Contact with these hosts is not authorized for this engagement. Report the block to the "
                  "user and do not work around it. Only the user can widen the scope, with /appaudit:scope, "
                  "after confirming written authorization.")
        log(pdir, scope, data, "blocked", hosts, reason)
        decide("deny", reason)
        return

    unsure = []
    for host in sorted(soft_hosts - hosts):
        ok, why = ac.classify(host, scope, now)
        if not ok:
            unsure.append(why)
    unsure += soft_reasons
    if unsure:
        reason = ("appaudit scope guard cannot confirm that this call stays in scope: " + "; ".join(unsure) + ". "
                  "Approve only if every host this command contacts is inside the engagement scope and window.")
        log(pdir, scope, data, "approval_requested", soft_hosts, reason)
        decide("ask", reason)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001 - fail closed during an open or unknown engagement
        try:
            pdir = ac.project_dir({})
            open_or_unknown = (pdir / ac.SCOPE_REL).exists()
        except Exception:  # noqa: BLE001
            open_or_unknown = True
        if open_or_unknown:
            decide("deny", f"appaudit scope guard error ({exc.__class__.__name__}); the call was blocked to be safe. "
                           "Tell the user so they can check the plugin.")
        else:
            print(f"appaudit scope guard error: {exc}", file=sys.stderr)
    sys.exit(0)
