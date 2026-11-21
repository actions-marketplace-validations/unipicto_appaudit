#!/usr/bin/env python3
"""
vuln_intel.py — enrich CVE IDs with CISA KEV status, EPSS probability, and NVD CVSS.

Read-only lookups against public feeds (no auth required; NVD key optional).
Used in Phase 0/4 of the appaudit skill.

Usage:
    python vuln_intel.py CVE-2021-44228 CVE-2025-55182
    python vuln_intel.py --file cves.txt            # one CVE per line
    python vuln_intel.py CVE-... --json              # machine-readable output
    python vuln_intel.py CVE-... --no-nvd            # skip NVD (fast, no rate limit)

Environment:
    NVD_API_KEY   optional; raises the NVD rate limit (public tier ~5 req/30 s).
    HTTPS_PROXY   honoured automatically by urllib.

Feeds (see references/standards.md):
    KEV  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    EPSS https://api.first.org/data/v1/epss?cve=...     (cve param <= 2000 chars)
    NVD  https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=...
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_V4_CALC = "https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator"
UA = "appaudit/4.1.0 (+vuln_intel.py)"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)


def _get(url: str, headers: dict | None = None, timeout: int = 30) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def load_kev() -> dict[str, dict]:
    """Return {CVE: entry} from the CISA KEV JSON feed."""
    data = _get(KEV_URL, timeout=60)
    return {v["cveID"].upper(): v for v in data.get("vulnerabilities", [])}


def load_epss(cves: list[str]) -> dict[str, dict]:
    """Batch EPSS lookups, respecting the 2000-char cve parameter limit."""
    out: dict[str, dict] = {}
    batch: list[str] = []

    def flush():
        if not batch:
            return
        q = urllib.parse.urlencode({"cve": ",".join(batch)})
        data = _get(f"{EPSS_URL}?{q}")
        for row in data.get("data", []):
            out[row["cve"].upper()] = row
        batch.clear()

    for c in cves:
        if len(",".join(batch + [c])) > 1900:
            flush()
        batch.append(c)
    flush()
    return out


def load_nvd(cve: str, api_key: str | None) -> dict | None:
    headers = {"apiKey": api_key} if api_key else {}
    q = urllib.parse.urlencode({"cveId": cve})
    for attempt in range(3):
        try:
            data = _get(f"{NVD_URL}?{q}", headers=headers)
            vulns = data.get("vulnerabilities", [])
            return vulns[0]["cve"] if vulns else None
        except urllib.error.HTTPError as e:
            # NVD signals rate limiting with 403 (historically) or 429; honour Retry-After.
            if e.code in (429, 403) and attempt < 2:
                retry_after = e.headers.get("Retry-After") if e.headers else None
                try:
                    wait = float(retry_after) if retry_after else 6.0 * (attempt + 1)
                except ValueError:
                    wait = 6.0 * (attempt + 1)
                time.sleep(wait)
                continue
            raise
    return None


def cvss_from_nvd(cve_obj: dict | None) -> dict:
    """Prefer CVSS v4.0, then v3.1, then v3.0. Returns the first listed source (NVD or CNA).
    Since 15 Apr 2026 NVD enriches only prioritized CVEs, so this may be empty: fall back to
    the CNA record / CISA-ADP data and say so in the report."""
    if not cve_obj:
        return {}
    metrics = cve_obj.get("metrics", {})
    for key, ver in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
        if metrics.get(key):
            m = metrics[key][0]["cvssData"]
            return {"version": ver, "score": m.get("baseScore"), "severity": m.get("baseSeverity"),
                    "vector": m.get("vectorString")}
    return {}


def calculator_url(vector: str | None) -> str | None:
    """Pre-filled NVD v4.0 calculator link (NVD: based on the FIRST calculator)."""
    prefix = "CVSS:4.0/"
    if not vector or not vector.startswith(prefix):
        return None
    return f"{NVD_V4_CALC}?{urllib.parse.urlencode({'vector': vector[len(prefix):], 'version': '4.0'})}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cves", nargs="*", help="CVE IDs")
    ap.add_argument("--file", help="file with one CVE per line")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    ap.add_argument("--no-nvd", action="store_true", help="skip NVD lookups")
    ap.add_argument("--no-kev", action="store_true", help="skip KEV feed download")
    args = ap.parse_args()

    cves = [c.strip().upper() for c in args.cves]
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            cves += [ln.strip().upper() for ln in fh if ln.strip() and not ln.startswith("#")]
    cves = sorted({c for c in cves if CVE_RE.match(c)})
    if not cves:
        ap.error("no valid CVE IDs given (expected CVE-YYYY-NNNN)")

    errors: list[str] = []
    kev: dict[str, dict] = {}
    epss: dict[str, dict] = {}
    if not args.no_kev:
        try:
            kev = load_kev()
        except Exception as e:  # noqa: BLE001
            errors.append(f"KEV unavailable: {e}")
    try:
        epss = load_epss(cves)
    except Exception as e:  # noqa: BLE001
        errors.append(f"EPSS unavailable: {e}")

    api_key = os.environ.get("NVD_API_KEY")
    rows = []
    for i, c in enumerate(cves):
        nvd = None
        if not args.no_nvd:
            try:
                nvd = load_nvd(c, api_key)
                # stay under public rate limit without a key
                if not api_key and i < len(cves) - 1:
                    time.sleep(6)
            except Exception as e:  # noqa: BLE001
                errors.append(f"NVD {c}: {e}")
        k = kev.get(c)
        e = epss.get(c, {})
        cv = cvss_from_nvd(nvd)
        rows.append({
            "cve": c,
            "kev": bool(k),
            "kev_date_added": k.get("dateAdded") if k else None,
            "kev_ransomware": k.get("knownRansomwareCampaignUse") if k else None,
            "epss": float(e["epss"]) if e.get("epss") else None,
            "epss_percentile": float(e["percentile"]) if e.get("percentile") else None,
            "epss_date": e.get("date"),
            "cvss_version": cv.get("version"),
            "cvss_score": cv.get("score"),
            "cvss_severity": cv.get("severity"),
            "cvss_vector": cv.get("vector"),
            "calculator_url": calculator_url(cv.get("vector")),
        })

    if args.json:
        print(json.dumps({"results": rows, "errors": errors,
                          "sources": {"kev": KEV_URL, "epss": EPSS_URL, "nvd": NVD_URL}}, indent=2))
    else:
        print(f"{'CVE':<18}{'KEV':<6}{'EPSS':<8}{'Pctl':<7}{'CVSS':<6}{'Sev':<10}Vector")
        for r in rows:
            epss = "-" if r["epss"] is None else format(r["epss"], ".3f")
            pct = "-" if r["epss_percentile"] is None else format(r["epss_percentile"], ".2f")
            print(f"{r['cve']:<18}"
                  f"{('YES' if r['kev'] else 'no'):<6}"
                  f"{epss:<8}"
                  f"{pct:<7}"
                  f"{(str(r['cvss_score']) if r['cvss_score'] is not None else '-'):<6}"
                  f"{(r['cvss_severity'] or '-'):<10}"
                  f"{r['cvss_vector'] or '-'}")
        for err in errors:
            print(f"! {err}", file=sys.stderr)
    return 0 if not errors else 2


if __name__ == "__main__":
    sys.exit(main())
