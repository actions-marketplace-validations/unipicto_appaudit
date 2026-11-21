#!/usr/bin/env python3
"""appaudit merge step: combine candidate findings from parallel reviewers into findings.json.

Usage:
  python3 merge_candidates.py --findings .appaudit/findings.json \
      --candidates .appaudit/candidates/*.json [--scope .appaudit/scope.json] \
      [--regulatory .appaudit/candidates/regulatory.json] [--engagement engagement.json] [--prefix AA] [--dry-run]

--candidates  JSON files, each an array of candidate findings (reviewer output) or an object
              with a "findings" array. Globs are expanded by the shell or by this script.
--findings    Created if missing (engagement block filled from --scope); otherwise merged into.
--engagement  Engagement block to use when findings.json is created (for example the engagement.json
              that scan_extension.py writes for a static extension review); --scope is ignored then.
--regulatory  Output of the regulatory-mapper agent: {"AA-001": [flag, ...], ...}; replaces the
              regulatory[] (and disclosure[], if given) of the listed findings.

Duplicates are merged by root cause: same CWE set and same file (or URL), and either the same
normalized title or overlapping lines. The merged finding keeps the highest severity, the
highest confidence, the union of identifiers, sources and evidence references, and the most
complete remediation. New findings get the next free ID (AA-001, AA-002, ...); existing IDs
are never changed. Standard library only; Python 3.9+.
"""
from __future__ import annotations

import argparse
import glob
import json
import re
import sys
from pathlib import Path

SEV = ["Critical", "High", "Medium", "Low", "Informational"]
CONF = ["Confirmed", "Likely", "Informational"]
LIST_FIELDS = ("cwe", "owasp", "asvs", "opencre", "cve", "sources", "proof_steps")


def _norm(t) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(t or "").lower()).strip()


def _loc(f) -> tuple:
    loc = f.get("location") or {}
    uri = str(loc.get("uri") or "").replace("\\", "/").lstrip("./").lower()
    s = loc.get("start_line") if isinstance(loc.get("start_line"), int) else None
    e = loc.get("end_line") if isinstance(loc.get("end_line"), int) else s
    return uri, s, e


def same_root_cause(a: dict, b: dict) -> bool:
    if set(a.get("cwe") or []) != set(b.get("cwe") or []):
        return False
    (ua, sa, ea), (ub, sb, eb) = _loc(a), _loc(b)
    if ua != ub:
        return False
    if _norm(a.get("title")) == _norm(b.get("title")):
        return True
    if sa and sb:
        return not (ea < sb or eb < sa)  # line ranges overlap
    return False


def _better(a, b, order):
    ia = order.index(a) if a in order else len(order)
    ib = order.index(b) if b in order else len(order)
    return a if ia <= ib else b


def merge_into(base: dict, other: dict) -> dict:
    sb = SEV.index(base["severity"]) if base.get("severity") in SEV else len(SEV)
    so = SEV.index(other["severity"]) if other.get("severity") in SEV else len(SEV)
    if so < sb or (so == sb and len(str(other.get("title") or "")) > len(str(base.get("title") or ""))):
        for k in ("title", "description", "impact", "location"):
            if other.get(k):
                base[k] = other[k]
    base["severity"] = _better(base.get("severity"), other.get("severity"), SEV)
    base["confidence"] = _better(base.get("confidence"), other.get("confidence"), CONF)
    for k in LIST_FIELDS:
        vals = list(base.get(k) or [])
        vals += [v for v in other.get(k) or [] if v not in vals]
        if vals:
            base[k] = vals
    refs = {json.dumps(r, sort_keys=True) for r in base.get("evidence_refs") or []}
    for r in other.get("evidence_refs") or []:
        if json.dumps(r, sort_keys=True) not in refs:
            base.setdefault("evidence_refs", []).append(r)
    for k in ("description", "root_cause", "impact", "asset", "cvss_v4", "ssvc", "retest", "remediation"):
        if not base.get(k) and other.get(k):
            base[k] = other[k]
    rb, ro = base.get("remediation") or {}, other.get("remediation") or {}
    if len(str(ro.get("patch") or "")) > len(str(rb.get("patch") or "")):
        base["remediation"] = ro
    base.setdefault("merge_notes", []).append(f"merged duplicate from {', '.join(other.get('sources') or ['unknown'])}")
    return base


def load_candidates(paths) -> list:
    out = []
    for pattern in paths:
        for p in sorted(glob.glob(pattern)) or [pattern]:
            if Path(p).name == "regulatory.json":
                continue
            data = json.loads(Path(p).read_text(encoding="utf-8"))
            items = data.get("findings", []) if isinstance(data, dict) else data
            for f in items:
                f.setdefault("sources", [Path(p).stem])
                out.append(f)
    return out


def engagement_from_scope(scope: dict) -> dict:
    auth = scope.get("authorization") or {}
    return {
        "name": scope.get("engagement") or "engagement",
        "date": (scope.get("opened_at") or "")[:10] or None,
        "authorization": {"basis": auth.get("basis") or "none", "reference": auth.get("reference") or ""},
        "mode": scope.get("mode") or "static",
        "window": scope.get("window") or {},
        "scope": {"in": (scope.get("in_scope") or {}).get("hosts", []) + (scope.get("in_scope") or {}).get("cidrs", []),
                  "out": (scope.get("out_of_scope") or {}).get("hosts", []) + (scope.get("out_of_scope") or {}).get("cidrs", [])},
        "jurisdiction_profile": scope.get("jurisdiction_profile") or {},
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--findings", required=True)
    ap.add_argument("--candidates", nargs="*", default=[])
    ap.add_argument("--scope", default=None)
    ap.add_argument("--regulatory", default=None)
    ap.add_argument("--engagement", default=None)
    ap.add_argument("--prefix", default="AA")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    fpath = Path(args.findings)
    if fpath.exists():
        data = json.loads(fpath.read_text(encoding="utf-8"))
    else:
        if args.engagement:
            eng = json.loads(Path(args.engagement).read_text(encoding="utf-8"))
        else:
            scope = json.loads(Path(args.scope).read_text(encoding="utf-8")) if args.scope and Path(args.scope).exists() else {}
            eng = engagement_from_scope(scope)
        data = {"schema": "appaudit-findings/1", "engagement": eng, "findings": []}
    findings = data.setdefault("findings", [])

    added = merged = 0
    for cand in load_candidates(args.candidates):
        cand.pop("id", None) if not cand.get("id") else None
        target = next((f for f in findings if same_root_cause(f, cand)), None)
        if target is not None:
            merge_into(target, cand)
            merged += 1
        else:
            findings.append(cand)
            added += 1

    used = {f.get("id") for f in findings if f.get("id")}
    n = 1
    for f in findings:
        if not f.get("id"):
            while f"{args.prefix}-{n:03d}" in used:
                n += 1
            f["id"] = f"{args.prefix}-{n:03d}"
            used.add(f["id"])

    applied = 0
    if args.regulatory:
        reg = json.loads(Path(args.regulatory).read_text(encoding="utf-8"))
        by_id = {f["id"]: f for f in findings}
        for fid, flags in reg.items():
            if fid in by_id:
                if isinstance(flags, dict):
                    by_id[fid]["regulatory"] = flags.get("regulatory", [])
                    if "disclosure" in flags:
                        by_id[fid]["disclosure"] = flags["disclosure"]
                else:
                    by_id[fid]["regulatory"] = flags
                applied += 1

    result = {"findings_total": len(findings), "added": added, "merged_duplicates": merged,
              "regulatory_applied": applied, "written": not args.dry_run, "file": str(fpath)}
    if not args.dry_run:
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
