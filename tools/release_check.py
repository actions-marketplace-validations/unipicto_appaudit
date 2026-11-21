#!/usr/bin/env python3
"""Pre-release check: no personal data, no secrets, consistent versions, valid JSON.

  python3 tools/release_check.py

Personal data: put names, e-mail addresses, usernames, local paths or anything else that must
never be published in a git-ignored file `.release-deny` (one term per line) or in the
environment variable APPAUDIT_DENY (comma-separated). The check fails if any term appears in
any tracked text file. Generic checks always run: e-mail addresses, home-folder paths,
private keys and common token formats.
Exit code 0 = clean. Standard library only.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEXT = {".md", ".py", ".json", ".yml", ".yaml", ".txt", ".toml", ".cfg", ".gitignore", ""}
SKIP_DIRS = {".git", "dist", "__pycache__", ".appaudit", "node_modules"}
# Files that contain fake secrets on purpose (tests) or the redaction patterns themselves.
SECRET_ALLOW = {"tests/run_tests.py", "hooks/appaudit_common.py", "tools/release_check.py"}
EMAIL_ALLOW = re.compile(r"(@([a-z0-9-]+\.)*example\.(com|org|net|nl)$|^noreply@|@users\.noreply\.github\.com$)", re.I)

GENERIC = [
    ("e-mail address", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("Windows user folder", re.compile(r"[A-Za-z]:\\Users\\[^\\\s]+", re.I)),
    ("macOS user folder", re.compile(r"/Users/[A-Za-z0-9._-]+/")),
    ("Linux home folder", re.compile(r"/home/(?!runner/)[A-Za-z0-9._-]+/")),
]
SECRETS = [
    ("private key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("Slack token", re.compile(r"\bxox[abpr]-[A-Za-z0-9-]{10,}\b")),
    ("OpenAI/Anthropic key", re.compile(r"\bsk-(ant-)?[A-Za-z0-9_-]{20,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
]
FORBIDDEN_NAMES = {".env", "id_rsa", "id_ed25519", ".release-deny"}
FORBIDDEN_SUFFIX = {".pem", ".key", ".p12", ".pfx", ".pyc"}


def tracked_files():
    for p in sorted(ROOT.rglob("*")):
        rel = p.relative_to(ROOT)
        if p.is_file() and not (set(rel.parts) & SKIP_DIRS):
            yield p, rel.as_posix()


def deny_terms() -> list:
    terms = [t.strip() for t in os.environ.get("APPAUDIT_DENY", "").split(",") if t.strip()]
    f = ROOT / ".release-deny"
    if f.exists():
        terms += [l.strip() for l in f.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")]
    return terms


def skill_metadata() -> list:
    """Every SKILL.md (and the standalone build's renamed skill) must pass Claude's upload limits."""
    sys.path.insert(0, str(ROOT / "skills" / "assess" / "scripts"))
    from scan_extension import parse_frontmatter, skill_metadata_problems
    problems = []
    for f in sorted((ROOT / "skills").glob("*/SKILL.md")):
        fm, _ = parse_frontmatter(f.read_text(encoding="utf-8"))
        names = [fm.get("name", "")] + (["appaudit"] if f.parent.name == "assess" else [])
        for n in names:
            for prob in skill_metadata_problems(n, fm.get("description", "")):
                problems.append(f"{f.relative_to(ROOT).as_posix()}: {prob}")
    from scan_extension import PLUGIN_DESCRIPTION_MAX
    for mf in (".claude-plugin/plugin.json", ".claude-plugin/marketplace.json"):
        d = json.loads((ROOT / mf).read_text(encoding="utf-8"))
        for entry in [d] + list(d.get("plugins", [])):
            n = len(str(entry.get("description", "")))
            if n > PLUGIN_DESCRIPTION_MAX:
                problems.append(f"{mf}: plugin description has {n} characters (maximum {PLUGIN_DESCRIPTION_MAX})")
    return sorted(set(problems))


def main() -> int:
    problems = skill_metadata()
    terms = deny_terms()
    for p, rel in tracked_files():
        if rel == ".release-deny":
            continue
        if p.name in FORBIDDEN_NAMES or p.suffix in FORBIDDEN_SUFFIX:
            problems.append(f"{rel}: file must not be published")
            continue
        if p.suffix not in TEXT and p.name not in {"LICENSE", "NOTICE"}:
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        for n, line in enumerate(text.splitlines(), 1):
            for t in terms:
                if t.lower() in line.lower():
                    problems.append(f"{rel}:{n}: denied term found")
            for label, rx in GENERIC:
                for m in rx.finditer(line):
                    if label == "e-mail address" and EMAIL_ALLOW.search(m.group(0)):
                        continue
                    problems.append(f"{rel}:{n}: {label}: {m.group(0)[:40]}")
            if rel not in SECRET_ALLOW:
                for label, rx in SECRETS:
                    if rx.search(line):
                        problems.append(f"{rel}:{n}: {label}")
        if p.suffix == ".json":
            try:
                json.loads(text)
            except ValueError as exc:
                problems.append(f"{rel}: invalid JSON ({exc})")

    version = json.loads((ROOT / ".claude-plugin/plugin.json").read_text())["version"]
    market = json.loads((ROOT / ".claude-plugin/marketplace.json").read_text())
    mv = next((e.get("version") for e in market.get("plugins", []) if e.get("name") == "appaudit"), None)
    if mv != version:
        problems.append(f"marketplace.json version {mv} != plugin.json {version}")
    for skill in sorted((ROOT / "skills").glob("*/SKILL.md")):
        m = re.search(r'^\s*version:\s*"([^"]+)"', skill.read_text(encoding="utf-8"), re.M)
        if not m or m.group(1) != version:
            problems.append(f"{skill.relative_to(ROOT)}: metadata.version {m.group(1) if m else 'missing'} != {version}")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8") if (ROOT / "CHANGELOG.md").exists() else ""
    if f"## [{version}]" not in changelog:
        problems.append(f"CHANGELOG.md has no '## [{version}]' entry")
    for need in ("LICENSE", "NOTICE", "README.md", "SECURITY.md"):
        if not (ROOT / need).exists():
            problems.append(f"{need} is missing")

    if problems:
        print("release_check: FAILED")
        for pr in problems:
            print("  - " + pr)
        return 1
    print(f"release_check: clean (version {version}; {len(terms)} private deny terms checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
