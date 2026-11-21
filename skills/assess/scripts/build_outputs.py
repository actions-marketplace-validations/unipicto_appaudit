#!/usr/bin/env python3
"""appaudit output builder: findings.json -> the six default outputs + update check.

Outputs, in a new folder <out>/<YYYY-MM-DD>-<engagement>/ (never overwrites a previous run):
  brief.md, report.md, findings.json, findings.sarif, findings-register.xlsx,
  evidence-bundle.zip, update-check.json, MANIFEST.sha256

Usage:
  python3 build_outputs.py --findings .appaudit/findings.json [--scope .appaudit/scope.json]
      [--evidence .appaudit/evidence/evidence.jsonl] [--out .appaudit/reports]
      [--update-source URL_OR_PATH] [--update-check-file PATH] [--plugin-root DIR]
      [--previous OLD/findings.json] [--attach FILE ...] [--no-update-check]

The update check runs first in every assessment (SKILL.md Step 0) and saves its result to
.appaudit/update-check.json; the builder reuses a result from the same day instead of
calling the network again. --previous adds a re-test comparison (delta.md, delta.json).
--attach copies supporting files (for example the inventory.json and capabilities.md written by
scan_extension.py) into attachments/, the evidence bundle and MANIFEST.sha256, and lists them
in the report appendix.

Exit codes: 0 built; 2 findings.json has errors (nothing written).
Standard library only; Python 3.9+. Network is used only for the optional update check.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import urllib.parse
import zipfile
from datetime import date, datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape as _xml_escape

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_update  # noqa: E402
import compare_runs  # noqa: E402

SCHEMA = "appaudit-findings/1"
SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]
CONFIDENCE = ["Confirmed", "Likely", "Informational"]
VERDICTS = ["Confirmed", "Likely", "Needs evidence", "Rejected"]
SSVC_RANK = {"Act": 0, "Attend": 1, "Track*": 2, "Track": 3}
TIERS = ["may_trigger_now", "readiness"]
NVD_V4_CALC = "https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator"
SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
GENESIS = "0" * 64
EU_MEMBERS = {"AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV",
              "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE", "EU"}
COVERED = {"US", "UK", "GB", "CA", "AU", "SG", "JP", "IN"}
WARNINGS_ONLY = {"CN"}


# ------------------------------------------------------------------ helpers

def band(score):
    if score is None:
        return None
    if score == 0:
        return "Informational"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def calculator_url(vector):
    prefix = "CVSS:4.0/"
    if not vector or not str(vector).startswith(prefix):
        return None
    return f"{NVD_V4_CALC}?{urllib.parse.urlencode({'vector': vector[len(prefix):], 'version': '4.0'})}"


def slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (text or "engagement").lower()).strip("-")
    return s[:60] or "engagement"


def md(text) -> str:
    """Make a value safe for one Markdown table cell."""
    if text is None:
        return ""
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def get(d, *keys, default=None):
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k)
    return d if d is not None else default


# ------------------------------------------------------------------ validation

def validate(data: dict, plugin_mode: bool):
    errors, warnings = [], []
    if data.get("schema") != SCHEMA:
        errors.append(f'schema must be "{SCHEMA}"')
    eng = data.get("engagement")
    if not isinstance(eng, dict):
        errors.append("engagement object is missing")
        eng = {}
    for key in ("name", "date", "mode"):
        if not eng.get(key):
            errors.append(f"engagement.{key} is missing")
    if eng.get("mode") not in (None, "static", "active"):
        errors.append("engagement.mode must be static or active")
    if not get(eng, "authorization", "basis"):
        errors.append("engagement.authorization.basis is missing")
    if eng.get("date"):
        try:
            date.fromisoformat(eng["date"])
        except ValueError:
            errors.append("engagement.date must be YYYY-MM-DD")
    if not eng.get("jurisdiction_profile"):
        warnings.append("no jurisdiction_profile: regulatory triggers are reported as not assessed")

    inst = get(data, "summary", "install_decision", default=None)
    if inst is not None and (not isinstance(inst, dict) or inst.get("decision") not in INSTALL_LABELS):
        errors.append(f"summary.install_decision.decision must be one of {list(INSTALL_LABELS)}")
    findings = data.get("findings")
    if not isinstance(findings, list):
        errors.append("findings must be a list")
        findings = []
    seen = set()
    for i, f in enumerate(findings):
        ref = f.get("id") or f"findings[{i}]"
        if not f.get("id"):
            errors.append(f"{ref}: id is missing")
        elif f["id"] in seen:
            errors.append(f"{ref}: duplicate id")
        seen.add(f.get("id"))
        if not f.get("title"):
            errors.append(f"{ref}: title is missing")
        if f.get("severity") not in SEVERITIES:
            errors.append(f"{ref}: severity must be one of {SEVERITIES}")
        if f.get("confidence") not in CONFIDENCE:
            errors.append(f"{ref}: confidence must be one of {CONFIDENCE}")
        cv = f.get("cvss_v4") or {}
        if cv.get("vector") and not str(cv["vector"]).startswith("CVSS:4.0/"):
            errors.append(f"{ref}: cvss_v4.vector must start with CVSS:4.0/")
        score = cv.get("score")
        if score is not None:
            if not isinstance(score, (int, float)) or not 0 <= score <= 10:
                errors.append(f"{ref}: cvss_v4.score must be a number 0-10")
            elif band(score) != f.get("severity"):
                warnings.append(f"{ref}: severity {f.get('severity')} does not match CVSS band {band(score)} for score {score}")
        elif cv.get("vector"):
            warnings.append(f"{ref}: CVSS vector given without a score; compute it with the FIRST v4.0 calculator")
        decision = get(f, "ssvc", "decision")
        if decision and decision not in SSVC_RANK:
            errors.append(f"{ref}: ssvc.decision must be one of {list(SSVC_RANK)}")
        if get(f, "kev", "listed") and decision in ("Track", "Track*"):
            errors.append(f"{ref}: KEV-listed findings are never below Attend (scoring-and-triage.md §2)")
        verdict = get(f, "verifier", "verdict")
        if verdict and verdict not in VERDICTS:
            errors.append(f"{ref}: verifier.verdict must be one of {VERDICTS}")
        if plugin_mode and not verdict and f.get("severity") != "Informational":
            errors.append(f"{ref}: plugin runs require a verifier verdict (appaudit:verifier)")
        if verdict == "Likely" and f.get("confidence") == "Confirmed":
            errors.append(f"{ref}: confidence Confirmed is above the verifier verdict Likely")
        if verdict in ("Rejected", "Needs evidence") and f.get("status", "open") == "open":
            warnings.append(f"{ref}: verifier verdict is {verdict}; resolve it or move the item to verified_not_applicable")
        for j, r in enumerate(f.get("regulatory") or []):
            if r.get("tier") not in TIERS:
                errors.append(f"{ref}: regulatory[{j}].tier must be one of {TIERS}")
            if r.get("decided_by") != "client/counsel":
                errors.append(f'{ref}: regulatory[{j}].decided_by must be "client/counsel"')
            for k in ("jurisdiction", "instrument", "basis"):
                if not r.get(k):
                    errors.append(f"{ref}: regulatory[{j}].{k} is missing")
        loc = f.get("location") or {}
        if loc.get("kind") == "file" and not loc.get("uri"):
            errors.append(f"{ref}: location.kind file needs location.uri")
    return errors, warnings


def coverage(eng: dict) -> tuple:
    """Jurisdictions from the profile that this version covers, covers with warnings only, or not at all."""
    prof = eng.get("jurisdiction_profile") or {}
    codes = set()
    for k in ("established_in", "markets", "data_subject_regions", "hosting_locations"):
        codes |= {str(c).upper() for c in prof.get(k) or []}
    covered, warn, missing = set(), set(), set()
    for c in codes:
        base = c.split("-")[0]
        if c in EU_MEMBERS or base in COVERED:
            covered.add(c)
        elif base in WARNINGS_ONLY:
            warn.add(c)
        else:
            missing.add(c)
    return sorted(covered), sorted(warn), sorted(missing)


def normalize(data: dict) -> dict:
    for f in data.get("findings", []):
        f.setdefault("status", "open")
        cv = f.get("cvss_v4")
        if isinstance(cv, dict) and cv.get("vector") and not cv.get("calculator_url"):
            cv["calculator_url"] = calculator_url(cv["vector"])

    def key(f):
        return (SSVC_RANK.get(get(f, "ssvc", "decision"), 9),
                -(get(f, "cvss_v4", "score") or -1),
                SEVERITIES.index(f.get("severity", "Informational")),
                f.get("id", ""))
    data["findings"] = sorted(data.get("findings", []), key=key)
    eng = data.get("engagement", {})
    covered, warn, missing = coverage(eng)
    if eng.get("jurisdiction_profile"):
        if not eng.get("jurisdictions_assessed"):
            eng["jurisdictions_assessed"] = covered
        na = set(eng.get("jurisdictions_not_assessed") or []) | set(missing) | {f"{c} (warnings only)" for c in warn}
        eng["jurisdictions_not_assessed"] = sorted(na)
    summary = data.setdefault("summary", {})
    if not summary.get("posture"):
        sev = [f["severity"] for f in data["findings"] if f.get("status") == "open" and f["severity"] != "Informational"]
        summary["posture"] = next((s for s in SEVERITIES if s in sev), "Low")
    return data


# ------------------------------------------------------------------ evidence

def verify_chain(path: Path | None) -> dict:
    res = {"file": str(path) if path else None, "records": 0, "head_sha256": None, "verified": None,
           "first_error": None, "blocked_calls": 0}
    if not path or not path.exists():
        res["first_error"] = "no evidence log"
        return res
    prev, seq = GENESIS, 1
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                res.update(verified=False, first_error=f"line {lineno}: not valid JSON")
                return res
            body = {k: v for k, v in rec.items() if k != "hash"}
            digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
            if rec.get("seq") != seq or rec.get("prev") != prev or rec.get("hash") != digest:
                res.update(verified=False, first_error=f"record {seq}: chain broken")
                return res
            if rec.get("event") == "blocked":
                res["blocked_calls"] += 1
            prev, seq = rec["hash"], seq + 1
            res["records"] += 1
    res.update(verified=True, head_sha256=prev if res["records"] else None)
    return res


# ------------------------------------------------------------------ text outputs

def counts(findings):
    table = {s: {"Confirmed": 0, "Likely": 0, "Informational": 0} for s in SEVERITIES}
    ssvc = {k: 0 for k in SSVC_RANK}
    for f in findings:
        if f.get("status") in ("false_positive",):
            continue
        table[f["severity"]][f["confidence"]] += 1
        d = get(f, "ssvc", "decision")
        if d in ssvc:
            ssvc[d] += 1
    return table, ssvc


def flags(findings, tier):
    out = []
    for f in findings:
        for r in f.get("regulatory") or []:
            if r.get("tier") == tier:
                out.append((f, r))
    return out


def tool_line(meta):
    return (f"appaudit {meta['version']} (standards checked {meta.get('standards_checked') or 'n/a'}, "
            f"regulatory data checked {meta.get('regulatory_checked') or 'n/a'})")


INSTALL_LABELS = {"do_not_install": "Do not install", "install_with_conditions": "Install only after the conditions below are met",
                  "no_blocking_issue_found": "No blocking issue found (not a guarantee of safety)"}


def build_brief(data, meta, chain, update, warnings, delta=None) -> str:
    eng, summ, fs = data["engagement"], data.get("summary", {}), data["findings"]
    auth = eng.get("authorization", {})
    L = [f"# Security assessment brief — {eng['name']}", "",
         f"**Target:** {eng.get('target', '—')} · **Date:** {eng['date']} · **Assessor:** {eng.get('assessor', '—')}  ",
         f"**Permission to test (declared by the assessor, not verified by appaudit):** {auth.get('basis')} ({auth.get('reference', 'no reference')}) · **Mode:** {eng.get('mode')} · **Tool:** {tool_line(meta)}", ""]
    if update.get("status") == "update_available":
        L += [f"> **Update available:** {update.get('summary') or 'see ' + check_update.RELEASES_URL}", ""]
    if summ.get("assessor_summary"):
        L += [summ["assessor_summary"], ""]
    if delta:
        L += [f"**Re-test:** {compare_runs.summary_line(delta)} Details: `delta.md`.", ""]
    inst = summ.get("install_decision") or {}
    if inst.get("decision"):
        label = INSTALL_LABELS.get(inst["decision"], inst["decision"])
        L += [f"**Install decision (for the user to take):** {label}." + (f" {inst.get('reason')}" if inst.get("reason") else ""), ""]
        if inst.get("conditions"):
            L += [f"- Condition: {c}" for c in inst["conditions"]] + [""]

    now = flags(fs, "may_trigger_now")
    L += ["## 1. Deadlines that may be running", ""]
    if now:
        L += ["For client/counsel decision. The plugin does not decide materiality or awareness.", "",
              "| Finding | Jurisdiction | Instrument | Deadline | Clock starts | Authority |",
              "|---|---|---|---|---|---|"]
        for f, r in now:
            L.append(f"| {md(f['id'])} | {md(r['jurisdiction'])} | {md(r['instrument'])} {md(r.get('provision'))} | {md(r.get('deadline'))} | {md(r.get('clock_start'))} | {md(r.get('authority'))} |")
    elif not eng.get("jurisdiction_profile"):
        L.append("Not assessed: no jurisdiction profile was given.")
    else:
        L.append("None flagged.")
    L.append("")

    table, ssvc = counts(fs)
    L += ["## 2. Overall posture", "", f"**{summ.get('posture')}**", "",
          "| Severity | Confirmed | Likely | Total |", "|---|---|---|---|"]
    for s in SEVERITIES:
        c = table[s]
        tot = c["Confirmed"] + c["Likely"] + c["Informational"]
        if tot:
            L.append(f"| {s} | {c['Confirmed']} | {c['Likely']} | {tot} |")
    L += ["", "SSVC: " + " · ".join(f"{k} {v}" for k, v in ssvc.items()), ""]

    top = [f for f in fs if f.get("status") == "open" and f["severity"] != "Informational"][:5]
    L += ["## 3. Top risks", ""]
    if top:
        L += ["| ID | Title | Severity (CVSS-BTE) | SSVC | KEV | Fix due |", "|---|---|---|---|---|---|"]
        for f in top:
            score = get(f, "cvss_v4", "score")
            L.append(f"| {md(f['id'])} | {md(f['title'])} | {f['severity']}{f' ({score})' if score is not None else ''} | "
                     f"{md(get(f, 'ssvc', 'decision', default='—'))} | {'Yes' if get(f, 'kev', 'listed') else 'No'} | {md(get(f, 'timeline', 'due', default='—'))} |")
    else:
        L.append("No open findings above Informational.")
    L.append("")

    decisions = list(summ.get("decisions_needed") or [])
    for f, r in now:
        decisions.append(f"Decide on {r['instrument']} ({r['jurisdiction']}) for {f['id']}: {r['basis']}.")
    for f in fs:
        for d in f.get("disclosure") or []:
            if d.get("conflict"):
                decisions.append(f"Resolve disclosure conflict for {f['id']}: {d['conflict']}.")
    L += ["## 4. Decisions needed", ""] + ([f"- {md(d)}" for d in decisions] or ["- None."]) + [""]

    ready = {}
    for f, r in flags(fs, "readiness"):
        ready.setdefault((r["jurisdiction"], r["instrument"]), []).append(f["id"])
    L += ["## 5. Prepare for", ""]
    L += [f"- {md(j)} — {md(i)}: {', '.join(ids)}" for (j, i), ids in ready.items()] or ["- Nothing flagged."]
    L.append("")

    L += ["## 6. Coverage", "",
          f"- Jurisdictions assessed: {', '.join(eng.get('jurisdictions_assessed') or []) or 'none'}",
          f"- **Jurisdictions not assessed:** {', '.join(eng.get('jurisdictions_not_assessed') or []) or 'none'}",
          f"- Not tested: {'; '.join(eng.get('not_tested') or []) or 'none listed'}",
          f"- Calls blocked by the scope guard: {chain.get('blocked_calls', 0)}", ""]

    ev = ("not used" if chain.get("verified") is None else
          f"{chain['records']} records, chain {'verified' if chain['verified'] else 'FAILED (' + str(chain['first_error']) + ')'}"
          + (f", head SHA-256 `{chain['head_sha256'][:16]}…`" if chain.get("head_sha256") else ""))
    up = update.get("status", "skipped")
    up_txt = {"up_to_date": "up to date", "update_available": f"**update available: {update.get('latest')}**",
              "not_configured": "switched off", "unreachable": "source unreachable",
              "ahead_of_source": "installed version is newer than the source", "skipped": "skipped"}.get(up, up)
    L += ["## 7. Integrity and version", "",
          f"- Evidence log: {ev}",
          f"- Update check: {up_txt}" + (" · data older than 90 days" if update.get("stale_data") else ""),
          "- SHA-256 of every deliverable: `MANIFEST.sha256`"]
    if warnings:
        L.append(f"- Build warnings: {len(warnings)} (see report appendix)")
    return "\n".join(L) + "\n"


def build_report(data, meta, chain, update, warnings, delta=None) -> str:
    eng, summ, fs = data["engagement"], data.get("summary", {}), data["findings"]
    auth = eng.get("authorization", {})
    table, ssvc = counts(fs)
    now, ready = flags(fs, "may_trigger_now"), flags(fs, "readiness")
    L = [f"# Security Assessment — {eng['name']}", "",
         f"**Date:** {eng['date']}  **Assessor:** {eng.get('assessor', '—')}  **Tool:** {tool_line(meta)}", "",
         "## 1. Executive summary", "",
         f"- **Overall posture:** {summ.get('posture')}",
         f"- **Permission to test (declared by the assessor, not verified by appaudit):** {auth.get('basis')} — {auth.get('reference', 'no reference')}",
         f"- **Mode:** {eng.get('mode')} · window {get(eng, 'window', 'start', default='—')} to {get(eng, 'window', 'end', default='—')}",
         f"- **Tested scope:** {', '.join(get(eng, 'scope', 'in', default=[])) or eng.get('target', '—')}",
         f"- **Out of scope / not tested:** {', '.join(get(eng, 'scope', 'out', default=[]) + (eng.get('not_tested') or [])) or 'none listed'}",
         f"- **Runtime capabilities used:** {', '.join(eng.get('capabilities_used') or []) or '—'}",
         f"- **Threat-intel refresh:** {eng.get('threat_intel_refreshed') or 'not available (EPSS/KEV unverified)'}",
         f"- **Jurisdictions assessed:** {', '.join(eng.get('jurisdictions_assessed') or []) or 'none'} · **not assessed:** {', '.join(eng.get('jurisdictions_not_assessed') or []) or 'none'}",
         f"- **Regulatory flags:** {len(now)} may trigger now · {len(ready)} readiness (for client/counsel decision)",
         "- **Totals:** " + ", ".join(f"{sum(table[s].values())} {s}" for s in SEVERITIES)
         + f" (Confirmed {sum(t['Confirmed'] for t in table.values())}, Likely {sum(t['Likely'] for t in table.values())}); SSVC "
         + ", ".join(f"{v} {k}" for k, v in ssvc.items()), ""]
    if summ.get("assessor_summary"):
        L += [summ["assessor_summary"], ""]

    L += ["## 2. Findings", ""]
    main = [f for f in fs if f["severity"] != "Informational"]
    info = [f for f in fs if f["severity"] == "Informational"]
    for f in main:
        cv, ss = f.get("cvss_v4") or {}, f.get("ssvc") or {}
        loc = f.get("location") or {}
        where = loc.get("uri", "—") + (f":{loc['start_line']}" if loc.get("start_line") else "")
        ids = "; ".join(x for x in [", ".join(f.get("cwe") or []), ", ".join(f.get("owasp") or []),
                                     ", ".join(f.get("asvs") or []), ", ".join(f.get("opencre") or []),
                                     ", ".join(f.get("cve") or [])] if x) or "—"
        sev = (f"CVSS-BTE {cv.get('score') if cv.get('score') is not None else '(score pending: FIRST calculator)'} `{cv.get('vector', '—')}`"
               + (f" · [verify]({cv['calculator_url']})" if cv.get("calculator_url") else "")) if cv else "—"
        epss = f.get("epss") or {}
        L += [f"### [{f['severity'].upper()}] {f['id']} {f['title']}", "",
              f"- **Identifiers:** {ids}",
              f"- **Severity:** {sev}",
              f"- **Priority:** SSVC {ss.get('decision', '—')} (Exploitation {ss.get('exploitation', '—')} / Automatable {ss.get('automatable', '—')} / "
              f"Technical Impact {ss.get('technical_impact', '—')} / Mission & Well-being {ss.get('mission_wellbeing', '—')}) · "
              f"EPSS {epss.get('probability', '—')} ({epss.get('percentile', '—')}, {epss.get('date', '—')}) · "
              f"KEV {'Yes, due ' + str(get(f, 'kev', 'due_date')) if get(f, 'kev', 'listed') else 'No'}",
              f"- **Confidence:** {f['confidence']} · verifier: {get(f, 'verifier', 'verdict', default='not run')}"
              + (f" ({get(f, 'verifier', 'notes')})" if get(f, "verifier", "notes") else ""),
              f"- **Asset / location:** {f.get('asset', '—')} · `{where}` · status {f.get('status')} · owner {f.get('owner', '—')}"]
        if f.get("description"):
            L.append(f"- **Description:** {f['description']}")
        if f.get("proof_steps"):
            L.append("- **Proof (benign):**")
            L += [f"  {n}. {s}" for n, s in enumerate(f["proof_steps"], 1)]
        L += [f"- **Root cause:** {f.get('root_cause', '—')}", f"- **Impact:** {f.get('impact', '—')}"]
        rem = f.get("remediation") or {}
        L.append(f"- **Remediation:** {rem.get('summary', '—')}")
        if rem.get("patch"):
            L += [f"  ```{rem.get('language', '')}"] + ["  " + x for x in rem["patch"].splitlines()] + ["  ```"]
        if rem.get("regression_note"):
            L.append(f"  Regression note: {rem['regression_note']}")
        L.append(f"- **Remediation timeline:** {get(f, 'timeline', 'basis', default='organisation-defined')} — due {get(f, 'timeline', 'due', default='—')}")
        rt = f.get("retest") or {}
        if rt:
            L.append(f"- **Re-test:** {rt.get('action', '—')} → expected: {rt.get('expected', '—')}" + (f" · result: {rt['result']}" if rt.get("result") else ""))
        regs = f.get("regulatory") or []
        L.append("- **Regulatory flags:** " + ("; ".join(f"{r['tier']}: {r['jurisdiction']} {r['instrument']} {r.get('provision', '')} — {r.get('deadline', '')}" for r in regs) or "none") + " (client/counsel decision)")
        for d in f.get("disclosure") or []:
            L.append(f"- **Disclosure:** {d.get('channel')} — {d.get('deadline', '')}" + (f" · CONFLICT: {d['conflict']}" if d.get("conflict") else ""))
        if f.get("evidence_refs"):
            L.append("- **Evidence:** log records " + ", ".join(str(e.get("log_seq")) for e in f["evidence_refs"]))
        L.append("")
    if not main:
        L += ["No findings above Informational.", ""]

    L += ["## 3. Informational / hardening", ""] + ([f"- {f['id']} {f['title']}: {get(f, 'remediation', 'summary', default='')}" for f in info] or ["- None."]) + [""]
    L += ["## 4. Verified not applicable", ""] + ([f"- {v.get('item')} — {v.get('reason')}" for v in data.get("verified_not_applicable") or []] or ["- None."]) + [""]
    L += ["## 5. Re-test plan", "", "| Finding | Re-test action | Expected result |", "|---|---|---|"]
    L += [f"| {md(f['id'])} | {md(get(f, 'retest', 'action'))} | {md(get(f, 'retest', 'expected'))} |" for f in main if f.get("retest")] + [""]

    L += ["## 6. Regulatory trigger register", "", "For client/counsel decision. The Tier column keeps the two tiers apart.", "",
          "| Finding | Tier | Jurisdiction | Instrument | Provision | Deadline | Basis | Source checked |", "|---|---|---|---|---|---|---|---|"]
    for f, r in now + ready:
        L.append(f"| {md(f['id'])} | {md(r['tier'])} | {md(r['jurisdiction'])} | {md(r['instrument'])} | {md(r.get('provision'))} | {md(r.get('deadline'))} | {md(r['basis'])} | {md(r.get('source_checked'))} |")
    if not (now or ready):
        L.append("| — | — | — | none flagged | | | | |")
    L += ["", f"Jurisdictions not assessed: {', '.join(eng.get('jurisdictions_not_assessed') or []) or 'none'}.", ""]

    L += ["## 7. Disclosure routing and conflicts", ""]
    dis = [(f, d) for f in fs for d in f.get("disclosure") or []]
    L += [f"- {f['id']}: {d.get('channel')} — {d.get('deadline', '')}" + (f" · conflict: {d['conflict']} (client/counsel)" if d.get("conflict") else "") for f, d in dis] or ["- No third-party disclosure recommended."]
    L.append("")

    ev = data.get("evidence") or {}
    L += ["## 8. Evidence & data handling", "",
          f"- Raw evidence stored at: {ev.get('raw_location', '—')}; access: {ev.get('access', '—')}",
          f"- Evidence log: {chain['records']} records; chain {'verified' if chain.get('verified') else ('not used' if chain.get('verified') is None else 'FAILED: ' + str(chain.get('first_error')))}"
          + (f"; head SHA-256 `{chain['head_sha256']}`" if chain.get("head_sha256") else "")
          + f"; calls blocked by the scope guard: {chain.get('blocked_calls', 0)}",
          f"- Secrets discovered: {ev.get('secrets_found', 0)}, all redacted; rotation recommended for: {', '.join(ev.get('rotation_recommended_for') or []) or 'none'}", ""]

    if delta:
        L += ["## 9. Re-test comparison", "", compare_runs.summary_line(delta), "",
              f"Fixed: {', '.join(i['id'] or '?' for i in delta['fixed']) or 'none'} · "
              f"New: {', '.join(i['id'] or '?' for i in delta['new']) or 'none'} · "
              f"Persisting: {', '.join(i['id'] or '?' for i in delta['persisting']) or 'none'}. Full table: `delta.md`.", ""]
    L += ["## Appendix — build checks and version", "",
          f"- Update check: {update.get('status')}" + (f" (installed {update.get('installed')}, latest {update.get('latest')})" if update.get("latest") else ""),
          *[f"- {a}" for a in update.get("advice", [])],
          *([f"- Warning: {w}" for w in warnings] or ["- No build warnings."]),
          *[f"- Attachment: `attachments/{a}`" for a in data.get("attachments", [])],
          "- SHA-256 of every deliverable: `MANIFEST.sha256`"]
    return "\n".join(L) + "\n"


# ------------------------------------------------------------------ SARIF

def build_sarif(data, meta) -> dict:
    rules, results, skipped = [], [], 0
    level = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "Informational": "note"}
    for f in data["findings"]:
        loc = f.get("location") or {}
        if loc.get("kind") != "file" or f.get("status") == "false_positive":
            skipped += 1
            continue
        score = get(f, "cvss_v4", "score")
        props = {"tags": ["security"] + (f.get("cwe") or []) + (f.get("owasp") or []),
                 "precision": {"Confirmed": "high", "Likely": "medium"}.get(f["confidence"], "low")}
        if score is not None:
            props["security-severity"] = f"{float(score):.1f}"
        rules.append({"id": f["id"], "name": re.sub(r"[^A-Za-z0-9]+", "", f["title"].title())[:80] or f["id"],
                      "shortDescription": {"text": f["title"][:300]},
                      "fullDescription": {"text": (f.get("description") or f["title"])[:1000]},
                      "help": {"text": get(f, "remediation", "summary", default="See report.md")[:1000]},
                      "properties": props})
        region = {k2: loc[k1] for k1, k2 in (("start_line", "startLine"), ("end_line", "endLine")) if isinstance(loc.get(k1), int)}
        physical = {"artifactLocation": {"uri": loc["uri"].replace("\\", "/")}}
        if region:
            physical["region"] = region
        fp = hashlib.sha256(f"{f['title']}|{loc['uri']}|{','.join(f.get('cwe') or [])}".encode()).hexdigest()
        results.append({"ruleId": f["id"], "level": level[f["severity"]],
                        "message": {"text": f"{f['title']}. {f.get('impact', '')}".strip()[:1000]},
                        "locations": [{"physicalLocation": physical}],
                        "partialFingerprints": {"appauditFinding/v1": fp},
                        "properties": {"confidence": f["confidence"], "ssvc": get(f, "ssvc", "decision"),
                                       "kev": bool(get(f, "kev", "listed")), "status": f.get("status")}})
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "appaudit", "version": str(meta["version"]), "rules": rules}},
                      "results": results,
                      "properties": {"engagement": data["engagement"]["name"], "non_code_findings_not_in_sarif": skipped}}]}


# ------------------------------------------------------------------ XLSX (minimal, stdlib)

_ILLEGAL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _col(n: int) -> str:
    s = ""
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def _sheet_xml(rows, widths) -> str:
    out = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
           '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">',
           '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>',
           "<cols>" + "".join(f'<col min="{i}" max="{i}" width="{w}" customWidth="1"/>' for i, w in enumerate(widths, 1)) + "</cols>",
           "<sheetData>"]
    for r, row in enumerate(rows, 1):
        cells = []
        for c, val in enumerate(row, 1):
            ref = f"{_col(c)}{r}"
            style = ' s="1"' if r == 1 else ' s="2"'
            if isinstance(val, (int, float)) and not isinstance(val, bool):
                cells.append(f'<c r="{ref}"{style}><v>{val}</v></c>')
            else:
                text = _xml_escape(_ILLEGAL.sub("", "" if val is None else str(val)))[:32000]
                cells.append(f'<c r="{ref}" t="inlineStr"{style}><is><t xml:space="preserve">{text}</t></is></c>')
        out.append(f'<row r="{r}">' + "".join(cells) + "</row>")
    out.append("</sheetData>")
    if rows:
        out.append(f'<autoFilter ref="A1:{_col(len(rows[0]))}{len(rows)}"/>')
    out.append("</worksheet>")
    return "".join(out)


def build_xlsx(data, path: Path) -> None:
    fs = data["findings"]
    head = ["ID", "Title", "Severity", "CVSS-BTE", "CVSS vector", "SSVC", "KEV", "EPSS", "Confidence", "Verifier",
            "Asset", "Location", "CWE", "OWASP", "Owner", "Timeline basis", "Due", "Status", "Re-test action",
            "Re-test result", "May trigger now", "Readiness"]
    rows = [head]
    for f in fs:
        loc = f.get("location") or {}
        regs = f.get("regulatory") or []
        rows.append([f["id"], f["title"], f["severity"], get(f, "cvss_v4", "score"), get(f, "cvss_v4", "vector"),
                     get(f, "ssvc", "decision"), "Yes" if get(f, "kev", "listed") else "No", get(f, "epss", "probability"),
                     f["confidence"], get(f, "verifier", "verdict"), f.get("asset"),
                     (loc.get("uri") or "") + (f":{loc['start_line']}" if loc.get("start_line") else ""),
                     ", ".join(f.get("cwe") or []), ", ".join(f.get("owasp") or []), f.get("owner"),
                     get(f, "timeline", "basis"), get(f, "timeline", "due"), f.get("status"),
                     get(f, "retest", "action"), get(f, "retest", "result"),
                     "; ".join(f"{r['jurisdiction']} {r['instrument']}" for r in regs if r.get("tier") == "may_trigger_now"),
                     "; ".join(f"{r['jurisdiction']} {r['instrument']}" for r in regs if r.get("tier") == "readiness")])
    reg_head = ["Finding", "Tier", "Jurisdiction", "Instrument", "Provision", "Deadline", "Clock starts", "Authority",
                "Basis", "Decided by", "Source", "Source checked"]
    reg = [reg_head]
    for f in fs:
        for r in f.get("regulatory") or []:
            reg.append([f["id"], r.get("tier"), r.get("jurisdiction"), r.get("instrument"), r.get("provision"),
                        r.get("deadline"), r.get("clock_start"), r.get("authority"), r.get("basis"),
                        r.get("decided_by"), r.get("source"), r.get("source_checked")])
    sheets = [("Findings", _sheet_xml(rows, [9, 50, 12, 10, 40, 9, 6, 8, 12, 14, 20, 30, 14, 18, 16, 22, 12, 12, 40, 20, 30, 30])),
              ("Regulatory", _sheet_xml(reg, [9, 16, 12, 28, 14, 36, 30, 28, 50, 14, 30, 14]))]
    files = {
        "[Content_Types].xml": '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        + "".join(f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' for i in range(1, len(sheets) + 1)) + "</Types>",
        "_rels/.rels": '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>',
        "xl/workbook.xml": '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
        + "".join(f'<sheet name="{n}" sheetId="{i}" r:id="rId{i}"/>' for i, (n, _) in enumerate(sheets, 1)) + "</sheets></workbook>",
        "xl/_rels/workbook.xml.rels": '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + "".join(f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i}.xml"/>' for i in range(1, len(sheets) + 1))
        + f'<Relationship Id="rId{len(sheets) + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>',
        "xl/styles.xml": '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="10"/><name val="Calibri"/></font><font><b/><sz val="10"/><name val="Calibri"/></font></fonts><fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FFDDE4EE"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="3"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>',
    }
    for i, (_, xml) in enumerate(sheets, 1):
        files[f"xl/worksheets/sheet{i}.xml"] = xml
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in files.items():
            z.writestr(name, content)


# ------------------------------------------------------------------ main

def tool_meta(plugin_root: Path | None) -> dict:
    root = plugin_root or Path(__file__).resolve().parent.parent
    info = check_update.installed_info(root)
    return {"version": info["installed"] or "unknown", "standards_checked": info["standards_checked"],
            "regulatory_checked": info["regulatory_checked"], "root": str(root)}


def new_run_dir(base: Path, eng: dict) -> Path:
    stem = f"{eng['date']}-{slug(eng['name'])}"
    path, n = base / stem, 2
    while path.exists():
        path, n = base / f"{stem}-{n}", n + 1
    path.mkdir(parents=True)
    return path


def load_or_run_update_check(args, meta, plugin_root, findings_path) -> dict:
    if args.no_update_check:
        return {"status": "skipped", "summary": "Update check skipped (--no-update-check).", "advice": []}
    saved = Path(args.update_check_file) if args.update_check_file else findings_path.parent / "update-check.json"
    if saved.exists():
        try:
            res = json.loads(saved.read_text(encoding="utf-8"))
            if res.get("checked_on") == date.today().isoformat() and res.get("status"):
                res.setdefault("summary", check_update.summary_line(res))
                return res
        except ValueError:
            pass
    installed = meta["version"] if meta["version"] != "unknown" else None
    return check_update.check(args.update_source, installed, plugin_root or Path(meta["root"]))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--findings", required=True)
    ap.add_argument("--scope", default=None)
    ap.add_argument("--evidence", default=None)
    ap.add_argument("--out", default=".appaudit/reports")
    ap.add_argument("--update-source", default="")
    ap.add_argument("--plugin-root", default=None)
    ap.add_argument("--update-check-file", default=None,
                    help="saved Step 0 result to reuse (default: update-check.json next to --findings)")
    ap.add_argument("--previous", default=None, help="findings.json of the previous run, for a re-test comparison")
    ap.add_argument("--attach", nargs="*", default=[], help="supporting files to include (e.g. scan inventory)")
    ap.add_argument("--no-update-check", action="store_true")
    args = ap.parse_args()

    out_parts = [p.lower() for p in Path(args.out).resolve().parts]
    if any(a == ".appaudit" and b == "evidence" for a, b in zip(out_parts, out_parts[1:])):
        print("ERROR: --out must not be inside .appaudit/evidence/", file=sys.stderr)
        return 2
    findings_path = Path(args.findings)
    try:
        data = json.loads(findings_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"ERROR: cannot read {findings_path}: {exc}", file=sys.stderr)
        return 2
    plugin_root = Path(args.plugin_root) if args.plugin_root and not args.plugin_root.startswith("${") else None
    plugin_mode = plugin_root is not None and (plugin_root / ".claude-plugin" / "plugin.json").exists()
    errors, warnings = validate(data, plugin_mode)
    if errors:
        print("findings.json has errors; nothing was written:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 2
    data = normalize(data)
    meta = tool_meta(plugin_root)
    data["tool"] = {"name": "appaudit", "version": meta["version"], "standards_checked": meta["standards_checked"],
                    "regulatory_checked": meta["regulatory_checked"],
                    "built_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}

    scope_path = Path(args.scope) if args.scope else None
    ev_path = Path(args.evidence) if args.evidence else None
    chain = verify_chain(ev_path)
    if chain.get("verified") is False:
        warnings.append(f"evidence log chain FAILED: {chain['first_error']}")
    update = load_or_run_update_check(args, meta, plugin_root, findings_path)
    delta = None
    if args.previous:
        try:
            delta = compare_runs.compare(json.loads(Path(args.previous).read_text(encoding="utf-8")), data)
        except (OSError, ValueError) as exc:
            warnings.append(f"re-test comparison skipped: cannot read {args.previous} ({exc.__class__.__name__})")

    attachments = []
    for a in args.attach:
        ap_ = Path(a)
        if not ap_.is_file():
            warnings.append(f"attachment skipped (not a file): {ap_.name}")
            continue
        name = re.sub(r"[^A-Za-z0-9._-]", "_", ap_.name)
        while name in {n for n, _ in attachments}:
            name = "x-" + name
        attachments.append((name, ap_))
    if attachments:
        data["attachments"] = [n for n, _ in attachments]

    out = new_run_dir(Path(args.out), data["engagement"])
    files = {
        "brief.md": build_brief(data, meta, chain, update, warnings, delta),
        "report.md": build_report(data, meta, chain, update, warnings, delta),
        "findings.json": json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        "findings.sarif": json.dumps(build_sarif(data, meta), indent=2, ensure_ascii=False) + "\n",
        "update-check.json": json.dumps(update, indent=2) + "\n",
    }
    if delta:
        files["delta.md"] = compare_runs.render_md(delta)
        files["delta.json"] = json.dumps(delta, indent=2, ensure_ascii=False) + "\n"
    for name, text in files.items():
        (out / name).write_bytes((text).encode("utf-8"))
    build_xlsx(data, out / "findings-register.xlsx")
    if attachments:
        (out / "attachments").mkdir()
        for name, src in attachments:
            (out / "attachments" / name).write_bytes(src.read_bytes())
    (out / "evidence-verification.json").write_text(json.dumps(chain, indent=2) + "\n", encoding="utf-8")

    deliverables = ["brief.md", "report.md", "findings.json", "findings.sarif", "findings-register.xlsx",
                    "update-check.json", "evidence-verification.json"] + (["delta.md", "delta.json"] if delta else []) \
        + [f"attachments/{n}" for n, _ in attachments]
    manifest_lines = [f"{sha256_file(out / n)}  {n}" for n in deliverables]
    extra = []
    if scope_path and scope_path.exists():
        manifest_lines.append(f"{sha256_file(scope_path)}  scope.json")
        extra.append((scope_path, "scope.json"))
    if ev_path and ev_path.exists():
        manifest_lines.append(f"{sha256_file(ev_path)}  evidence.jsonl")
        extra.append((ev_path, "evidence.jsonl"))
    inner_manifest = "\n".join(manifest_lines) + "\n"
    bundle = out / "evidence-bundle.zip"
    with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as z:
        for n in ("findings.json", "evidence-verification.json", "update-check.json") + tuple(f"attachments/{a}" for a, _ in attachments):
            z.write(out / n, n)
        for src, name in extra:
            z.write(src, name)
        z.writestr("MANIFEST.sha256", inner_manifest)
    (out / "evidence-verification.json").unlink()
    manifest = [l for l in manifest_lines if not l.endswith("evidence-verification.json")]
    manifest.append(f"{sha256_file(bundle)}  evidence-bundle.zip")
    (out / "MANIFEST.sha256").write_bytes(("\n".join(manifest) + "\n").encode("utf-8"))

    print(json.dumps({"output_dir": str(out), "files": sorted(p.name for p in out.iterdir()),
                      "evidence_bundle_sha256": sha256_file(bundle), "update_check": update.get("status"),
                      "warnings": warnings}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
