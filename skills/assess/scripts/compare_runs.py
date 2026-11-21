#!/usr/bin/env python3
"""appaudit re-test comparison: what changed between two findings.json files.

Usage:
  python3 compare_runs.py --previous OLD/findings.json --current NEW/findings.json
                          [--out DIR] [--json]

Writes delta.md and delta.json to --out (default: the folder of --current) and prints a
one-line summary. Findings are matched by ID first, then by title + location + CWE, so a
re-numbered finding is still recognised.

Categories:
  fixed        open before; status now fixed or false_positive
  not_retested open before; absent from the current run (no re-test evidence)
  new         not present before (or not open before and open now)
  persisting  open in both runs; severity, SSVC or KEV changes are listed
  accepted    open before; now status risk_accepted
Standard library only; Python 3.9+.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SEV = ["Critical", "High", "Medium", "Low", "Informational"]
CLOSED = {"fixed", "false_positive"}


def _norm(text) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(text or "").lower()).strip()


def _key(f: dict) -> tuple:
    loc = f.get("location") or {}
    return (_norm(f.get("title")), _norm(loc.get("uri")), ",".join(sorted(f.get("cwe") or [])))


def _status(f: dict | None) -> str:
    return (f or {}).get("status", "open") if f else "absent"


def _get(f, *keys):
    for k in keys:
        f = f.get(k) if isinstance(f, dict) else None
    return f


def _flags(f: dict) -> set:
    return {(r.get("tier"), r.get("jurisdiction"), r.get("instrument")) for r in f.get("regulatory") or []}


def match(prev: list, curr: list) -> list:
    """Return (previous, current) pairs; either side may be None."""
    pairs, used = [], set()
    by_id = {f.get("id"): i for i, f in enumerate(curr) if f.get("id")}
    by_key = {}
    for i, f in enumerate(curr):
        by_key.setdefault(_key(f), i)
    for p in prev:
        i = by_id.get(p.get("id"))
        # Same ID counts only when title or location also agree (IDs can be reused for other issues).
        if i is not None and (i in used or (_key(curr[i])[0] != _key(p)[0] and _key(curr[i])[1] != _key(p)[1])):
            i = None
        if i is None and by_key.get(_key(p)) is not None and by_key[_key(p)] not in used:
            i = by_key[_key(p)]
        if i is not None:
            used.add(i)
            pairs.append((p, curr[i]))
        else:
            pairs.append((p, None))
    pairs += [(None, f) for i, f in enumerate(curr) if i not in used]
    return pairs


def compare(previous: dict, current: dict) -> dict:
    out = {"previous": {"engagement": _get(previous, "engagement", "name"), "date": _get(previous, "engagement", "date"),
                        "tool_version": _get(previous, "tool", "version")},
           "current": {"engagement": _get(current, "engagement", "name"), "date": _get(current, "engagement", "date"),
                       "tool_version": _get(current, "tool", "version")},
           "fixed": [], "new": [], "persisting": [], "accepted": [], "not_retested": [], "regulatory_changes": []}
    for p, c in match(previous.get("findings") or [], current.get("findings") or []):
        ps, cs = _status(p), _status(c)
        ref = c or p
        item = {"id": ref.get("id"), "previous_id": (p or {}).get("id"), "title": ref.get("title"),
                "severity": ref.get("severity"), "ssvc": _get(ref, "ssvc", "decision")}
        if p is not None and ps == "open" and c is None:
            out["not_retested"].append(item)
        elif p is not None and ps == "open" and cs in CLOSED:
            item["evidence"] = _get(c, "retest", "result") or "no re-test result recorded"
            out["fixed"].append(item)
        elif p is not None and ps == "open" and cs == "risk_accepted":
            out["accepted"].append(item)
        elif c is not None and cs == "open" and ps != "open":
            out["new"].append(item)
        elif p is not None and c is not None and ps == "open" and cs == "open":
            changes = []
            for label, a, b in (("severity", p.get("severity"), c.get("severity")),
                                ("SSVC", _get(p, "ssvc", "decision"), _get(c, "ssvc", "decision")),
                                ("CVSS-BTE", _get(p, "cvss_v4", "score"), _get(c, "cvss_v4", "score")),
                                ("KEV", bool(_get(p, "kev", "listed")), bool(_get(c, "kev", "listed")))):
                if a != b:
                    changes.append(f"{label} {a} → {b}")
            item["changes"] = changes
            out["persisting"].append(item)
        if p is not None and c is not None:
            added, removed = _flags(c) - _flags(p), _flags(p) - _flags(c)
            for t, j, i in sorted(x for x in added if x[0]):
                out["regulatory_changes"].append({"id": c.get("id"), "change": "added", "tier": t, "jurisdiction": j, "instrument": i})
            for t, j, i in sorted(x for x in removed if x[0]):
                out["regulatory_changes"].append({"id": c.get("id"), "change": "removed", "tier": t, "jurisdiction": j, "instrument": i})
    sev_rank = {s: n for n, s in enumerate(SEV)}
    for k in ("fixed", "new", "persisting", "accepted", "not_retested"):
        out[k].sort(key=lambda x: (sev_rank.get(x.get("severity"), 9), str(x.get("id"))))
    out["totals"] = {k: len(out[k]) for k in ("fixed", "new", "persisting", "accepted", "not_retested")}
    return out


def summary_line(d: dict) -> str:
    t = d["totals"]
    return (f"Compared with the run of {d['previous']['date'] or 'unknown date'}: {t['fixed']} fixed, {t['new']} new, "
            f"{t['persisting']} persisting, {t['accepted']} risk-accepted, {t['not_retested']} not re-tested.")


def render_md(d: dict) -> str:
    def esc(x):
        return str(x if x is not None else "").replace("|", "\\|").replace("\n", " ")
    L = ["# Re-test comparison", "",
         f"Previous: {d['previous']['engagement']} ({d['previous']['date']}, appaudit {d['previous']['tool_version'] or 'n/a'})  ",
         f"Current: {d['current']['engagement']} ({d['current']['date']}, appaudit {d['current']['tool_version'] or 'n/a'})", "",
         summary_line(d), ""]
    for title, key, extra in (("Fixed", "fixed", "evidence"), ("New", "new", None),
                              ("Persisting", "persisting", "changes"), ("Risk accepted", "accepted", None),
                              ("Not re-tested", "not_retested", None)):
        L += [f"## {title} ({len(d[key])})", ""]
        if not d[key]:
            L += ["None.", ""]
            continue
        head = "| ID | Title | Severity | SSVC |" + (" Notes |" if extra else "")
        L += [head, "|" + "---|" * (head.count("|") - 1)]
        for it in d[key]:
            note = it.get(extra) if extra else None
            if isinstance(note, list):
                note = "; ".join(note) or "no change"
            row = f"| {esc(it['id'])} | {esc(it['title'])} | {esc(it['severity'])} | {esc(it['ssvc'])} |"
            L.append(row + (f" {esc(note)} |" if extra else ""))
        L.append("")
    L += ["## Regulatory flag changes", ""]
    L += [f"- {r['id']}: {r['change']} {r['tier']} — {r['jurisdiction']} {r['instrument']}" for r in d["regulatory_changes"]] or ["None."]
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--previous", required=True)
    ap.add_argument("--current", required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    try:
        prev = json.loads(Path(args.previous).read_text(encoding="utf-8"))
        curr = json.loads(Path(args.current).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    d = compare(prev, curr)
    out = Path(args.out) if args.out else Path(args.current).parent
    out.mkdir(parents=True, exist_ok=True)
    (out / "delta.json").write_text(json.dumps(d, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (out / "delta.md").write_text(render_md(d), encoding="utf-8")
    print(json.dumps(d, indent=2) if args.json else summary_line(d))
    return 0


if __name__ == "__main__":
    sys.exit(main())
