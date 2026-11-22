#!/usr/bin/env python3
"""appaudit update check: the first step of every assessment.

Reports whether a newer appaudit version is published on GitHub, and how old the standards
and regulatory data shipped with this copy are. It only reports; it never downloads or
installs anything.

Usage:
  python3 check_update.py [--source URL_OR_PATH | --offline] [--root DIR]
                          [--save PATH] [--json]

--source   Published plugin.json, marketplace.json or SKILL.md (https URL or local path).
           Default: the appaudit repository on GitHub (see DEFAULT_SOURCE).
           "off" or "none" disables the version comparison.
--offline  Same as --source off; still reports the age of the bundled data.
--root     Folder of the installed plugin or skill. Default: this script's skill folder.
--save     Also write the JSON result to this path (the output builder reuses it).
Standard library only; Python 3.9+. Network: one HTTPS GET to the source, nothing else.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path

REPO_URL = "https://github.com/unipicto/appaudit"
RELEASES_URL = REPO_URL + "/releases"
DEFAULT_SOURCE = "https://raw.githubusercontent.com/unipicto/appaudit/main/.claude-plugin/plugin.json"
UA = "appaudit-update-check/2 (+https://github.com/unipicto/appaudit)"
MAX_BYTES = 1_000_000
STALE_DAYS = 90
NAME = "appaudit"
OFF = {"off", "none", "disabled", "false", "0"}


def _parse_version(text: str):
    core = (text or "").strip().lstrip("vV").split("-")[0].split("+")[0]
    nums = re.findall(r"\d+", core)[:3]
    return tuple(int(n) for n in nums) + (0,) * (3 - len(nums)) if nums else None


def version_from_text(text: str) -> str | None:
    """Version from a plugin.json, a marketplace.json (entry named appaudit) or a SKILL.md."""
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if isinstance(data, dict):
        for entry in data.get("plugins") or []:
            if isinstance(entry, dict) and entry.get("name") == NAME and isinstance(entry.get("version"), str):
                return entry["version"]
        if isinstance(data.get("version"), str) and data.get("name", NAME) == NAME:
            return data["version"]
        return None
    m = re.search(r'^\s*version:\s*"?([0-9][^"\s]*)"?', text, re.M)
    return m.group(1) if m else None


def _read_source(source: str) -> str:
    if re.match(r"^https://", source, re.I):
        req = urllib.request.Request(source, headers={"User-Agent": UA, "Accept": "application/json, text/plain"})
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 - https only, read-only
            return resp.read(MAX_BYTES + 1)[:MAX_BYTES].decode("utf-8", "replace")
    if re.match(r"^[a-z]+://", source, re.I):
        raise ValueError("only https:// URLs or local paths are accepted")
    return Path(source).expanduser().read_text(encoding="utf-8")[:MAX_BYTES]


def installed_info(root: Path | None = None) -> dict:
    """Installed version and data dates, from a plugin root or a skill folder."""
    info = {"installed": None, "standards_checked": None, "regulatory_checked": None}
    root = root or Path(__file__).resolve().parent.parent
    manifest = root / ".claude-plugin" / "plugin.json"
    if manifest.exists():
        try:
            info["installed"] = json.loads(manifest.read_text(encoding="utf-8")).get("version")
        except ValueError:
            pass
    for d in (root, root / "skills" / "assess"):
        skill = d / "SKILL.md"
        if not skill.exists():
            continue
        text = skill.read_text(encoding="utf-8")
        if info["installed"] is None:
            m = re.search(r'^\s*version:\s*"([^"]+)"', text, re.M)
            info["installed"] = m.group(1) if m else None
        m = re.search(r'standards-checked:\s*"(\d{4}-\d{2}-\d{2})"', text)
        info["standards_checked"] = m.group(1) if m else None
        idx = d / "references" / "regulatory" / "index.md"
        if idx.exists():
            m = re.search(r"Regulatory data checked:\s*\*\*(\d{4}-\d{2}-\d{2})\*\*", idx.read_text(encoding="utf-8"))
            info["regulatory_checked"] = m.group(1) if m else None
        break
    return info


def _age(day: str | None, today: date) -> int | None:
    try:
        return (today - date.fromisoformat(day)).days if day else None
    except ValueError:
        return None


def summary_line(res: dict) -> str:
    inst, latest, st = res.get("installed") or "unknown", res.get("latest"), res.get("status")
    line = {
        "up_to_date": f"appaudit {inst} is up to date.",
        "update_available": f"appaudit {latest} is available (installed {inst}): see {RELEASES_URL}. Continuing with {inst}.",
        "ahead_of_source": f"appaudit {inst} is newer than the published version {latest}.",
        "unreachable": f"Update check not possible here (source unreachable); installed {inst}. Check {RELEASES_URL} manually.",
        "not_published": f"No published appaudit version found at the update source; installed {inst}. See {RELEASES_URL}.",
        "not_configured": f"Update check switched off; installed {inst}. Check {RELEASES_URL} manually.",
        "unknown": f"Update check could not compare versions; installed {inst}. Check {RELEASES_URL} manually.",
    }.get(st, f"appaudit {inst}: update check {st}.")
    if res.get("stale_data"):
        line += f" Bundled standards or regulatory data is older than {STALE_DAYS} days: re-verify before citing."
    return line


def check(source: str | None = None, installed: str | None = None, root: Path | None = None,
          today: date | None = None) -> dict:
    today = today or date.today()
    info = installed_info(root)
    installed = installed or info["installed"]
    source = (source or "").strip() or DEFAULT_SOURCE
    if source.startswith("${"):  # unsubstituted plugin option
        source = DEFAULT_SOURCE
    res = {
        "checked_on": today.isoformat(), "installed": installed, "latest": None,
        "source": None if source.lower() in OFF else source, "repository": REPO_URL,
        "status": None,
        "data_checked": {"standards": info["standards_checked"], "regulatory": info["regulatory_checked"]},
        "data_age_days": {"standards": _age(info["standards_checked"], today),
                          "regulatory": _age(info["regulatory_checked"], today)},
        "stale_data": False, "advice": [],
    }
    if any(a is not None and a > STALE_DAYS for a in res["data_age_days"].values()):
        res["stale_data"] = True
        res["advice"].append(f"Standards or regulatory data is older than {STALE_DAYS} days: re-verify before citing in a client report.")
    if source.lower() in OFF:
        res["status"] = "not_configured"
    else:
        try:
            latest = version_from_text(_read_source(source))
        except urllib.error.HTTPError as exc:
            res["status"] = "not_published" if exc.code == 404 else "unreachable"
            res["advice"].append(f"Update source answered HTTP {exc.code}.")
            latest = None
        except Exception as exc:  # noqa: BLE001 - report, never fail the run
            res["status"] = "unreachable"
            res["advice"].append(f"Could not read the update source ({exc.__class__.__name__}).")
            latest = None
        if res["status"] is None:
            res["latest"] = latest
            a, b = _parse_version(installed or ""), _parse_version(latest or "")
            if a is None or b is None:
                res["status"] = "unknown"
            elif b > a:
                res["status"] = "update_available"
                res["advice"].append("Review the changelog and verify the release hash before updating; this check never installs anything.")
            elif b < a:
                res["status"] = "ahead_of_source"
            else:
                res["status"] = "up_to_date"
    res["summary"] = summary_line(res)
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", default="")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--installed", default=None)
    ap.add_argument("--root", default=None)
    ap.add_argument("--save", default=None)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    res = check("off" if args.offline else args.source, args.installed, Path(args.root) if args.root else None)
    if args.save:
        out = Path(args.save)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(res, indent=2) if args.json else res["summary"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
