#!/usr/bin/env python3
"""Build the appaudit release packages into dist/ (reproducible: byte-identical on every OS and Python version).

  python3 tools/build_dist.py [--out dist]

Produces, for version V from .claude-plugin/plugin.json:
  appaudit-V.plugin            Claude Code / Cowork plugin (runtime files only)
  appaudit-skill-V.zip         standalone Agent Skill folder `appaudit/` (claude.ai, Codex,
                               Gemini CLI, GitHub Copilot, Cursor and other SKILL.md readers)
  appaudit-portable-V.zip      ChatGPT / Gemini / Grok / other assistants: system prompt,
                               10 knowledge files, optional scripts, setup guide
  SHA256SUMS                   hashes of the three packages
Run tools/release_check.py first; this script refuses to build if it fails. Each package users
install is then scanned with skills/assess/scripts/scan_extension.py; any Low-or-higher candidate
stops the build (release gate for OWASP AST08).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ASSESS = ROOT / "skills" / "assess"
REF = ASSESS / "references"
FIXED_TIME = (2026, 1, 1, 0, 0, 0)
SKIP_PARTS = {"__pycache__", ".appaudit", ".git", "dist", ".DS_Store"}
PLUGIN_PARTS = [".claude-plugin", "agents", "hooks", "scripts", "skills", "README.md", "LICENSE", "NOTICE", "CHANGELOG.md"]
SCRIPTS = ["check_update.py", "build_outputs.py", "merge_candidates.py", "compare_runs.py", "vuln_intel.py", "scan_extension.py"]


def files_under(path: Path):
    if path.is_file():
        yield path
        return
    for p in sorted(path.rglob("*")):
        if p.is_file() and not (set(p.relative_to(ROOT).parts) & SKIP_PARTS) and p.suffix != ".pyc":
            yield p


# Reproducible packages: the same commit gives byte-identical files on every OS and Python version.
# - Entries are STORED, not deflated: deflate output depends on the zlib build (classic zlib on the
#   GitHub runner, zlib-ng in many Python 3.13+ builds), so compressed bytes differ for identical files.
# - Fixed timestamp, sorted names, fixed permissions and a fixed "created on Unix" marker.
# - Text files are normalised to LF line endings, so a Windows checkout with CRLF gives the same bytes.
BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".xlsx", ".docx", ".gz", ".woff", ".woff2"}


def normalise(arc: str, data: bytes) -> bytes:
    if Path(arc).suffix.lower() in BINARY_SUFFIXES or b"\0" in data:
        return data
    return data.replace(b"\r\n", b"\n")


def write_zip(target: Path, entries) -> None:
    """entries: iterable of (arcname, bytes)."""
    with zipfile.ZipFile(target, "w", zipfile.ZIP_STORED) as z:
        for arc, data in sorted(entries, key=lambda e: e[0]):
            info = zipfile.ZipInfo(arc, FIXED_TIME)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3                      # Unix, whatever OS builds the package
            info.create_version = info.extract_version = 20
            info.external_attr = (0o755 if arc.endswith(".py") else 0o644) << 16
            z.writestr(info, normalise(arc, data))


def plugin_entries():
    for part in PLUGIN_PARTS:
        for p in files_under(ROOT / part):
            yield p.relative_to(ROOT).as_posix(), p.read_bytes()


def skill_entries(version: str):
    for p in files_under(ASSESS):
        rel = p.relative_to(ASSESS).as_posix()
        data = normalise(rel, p.read_bytes())   # before the rename below: `$` must not meet a `\r`
        if rel == "SKILL.md":
            text = data.decode("utf-8")
            text = re.sub(r"^name: assess$", "name: appaudit", text, count=1, flags=re.M)
            data = text.encode("utf-8")
        yield f"appaudit/{rel}", data
    yield "appaudit/README.md", (ROOT / "portable" / "SKILL-README.md").read_text(encoding="utf-8").replace("{{VERSION}}", version).encode()
    for name in ("LICENSE", "NOTICE"):
        yield f"appaudit/{name}", (ROOT / name).read_bytes()


def _cat(title: str, paths) -> bytes:
    parts = [f"# {title}\n"]
    for p in paths:
        parts.append(f"\n---\n\n<!-- source: {p.relative_to(ROOT).as_posix()} -->\n\n" + p.read_text(encoding="utf-8"))
    return "\n".join(parts).encode("utf-8")


def portable_entries(version: str):
    reg = REF / "regulatory"
    order = ["index.md", "eu.md", "nl.md", "us.md", "uk.md", "ca.md", "au.md", "sg.md", "jp.md", "in.md",
             "testing-law.md", "disclosure.md"]
    knowledge = {
        "01-core.md": _cat("appaudit core playbook (router, gate, guardrails, workflow)", [ASSESS / "SKILL.md"]),
        "02-web.md": _cat("Module: web applications", [REF / "module-web.md"]),
        "03-api-supply-chain.md": _cat("Module: APIs and software supply chain", [REF / "module-api-supply-chain.md"]),
        "04-mobile.md": _cat("Module: mobile and smart-device apps", [REF / "module-mobile-smart-device.md"]),
        "05-firmware.md": _cat("Module: embedded hardware and firmware", [REF / "module-hardware-firmware.md"]),
        "06-ai-agent.md": _cat("Modules: AI, LLM features and agents; AI-agent extensions",
                               [REF / "module-ai-agent.md", REF / "module-agent-extensions.md"]),
        "07-regulatory.md": _cat("Regulatory layer (all jurisdictions)", [reg / n for n in order]),
        "08-outputs.md": _cat("Scoring, findings schema and output layout",
                              [REF / "scoring-and-triage.md", REF / "findings-schema.md", REF / "report-template.md"]),
        "09-standards.md": _cat("Standards editions and refresh procedure", [REF / "standards.md"]),
        "10-findings-example.json": (REF / "findings-example.json").read_bytes(),
    }
    for name, data in knowledge.items():
        yield f"appaudit-portable/knowledge/{name}", data
    prompt = (ROOT / "portable" / "SYSTEM-PROMPT.md").read_text(encoding="utf-8").replace("{{VERSION}}", version)
    yield "appaudit-portable/SYSTEM-PROMPT.md", prompt.encode("utf-8")
    yield "appaudit-portable/SETUP.md", (ROOT / "docs" / "OTHER-ASSISTANTS.md").read_bytes()
    for s in SCRIPTS:
        yield f"appaudit-portable/scripts/{s}", (ASSESS / "scripts" / s).read_bytes()
    yield "appaudit-portable/scripts/findings.schema.json", (REF / "findings.schema.json").read_bytes()
    for name in ("LICENSE", "NOTICE"):
        yield f"appaudit-portable/{name}", (ROOT / name).read_bytes()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(ROOT / "dist"))
    ap.add_argument("--skip-check", action="store_true", help="do not run tools/release_check.py first")
    args = ap.parse_args()
    if not args.skip_check:
        r = subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "release_check.py")])
        if r.returncode != 0:
            print("release_check failed; nothing built.", file=sys.stderr)
            return 1
    version = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())["version"]
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    targets = {
        out / f"appaudit-{version}.plugin": plugin_entries(),
        out / f"appaudit-skill-{version}.zip": skill_entries(version),
        out / f"appaudit-portable-{version}.zip": portable_entries(version),
    }
    sums = []
    for target, entries in targets.items():
        write_zip(target, list(entries))
        if target.suffix in (".plugin", ".zip") and "portable" not in target.name:
            # Release gate (AST08): the package users install must scan clean with appaudit's own scanner.
            with tempfile.TemporaryDirectory() as tmp:
                g = subprocess.run([sys.executable, "-I", str(ASSESS / "scripts" / "scan_extension.py"), str(target),
                                    "--out", str(Path(tmp) / "scan"), "--fail-on", "Low"], capture_output=True, text=True)
            if g.returncode != 0:
                print(f"self-scan of {target.name} found Low-or-higher candidates; nothing published:\n{g.stdout[-1500:]}",
                      file=sys.stderr)
                target.unlink()
                return 1
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        sums.append(f"{digest}  {target.name}")
        print(f"{digest}  {target.name}  ({target.stat().st_size:,} bytes)")
    (out / "SHA256SUMS").write_bytes(("\n".join(sums) + "\n").encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
