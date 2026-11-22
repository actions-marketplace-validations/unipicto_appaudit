# Contributing

Thank you for helping. appaudit is used for client-facing security assessments, so accuracy
and traceability matter more than speed.

## What helps most

| Contribution | What we need |
|--------------|--------------|
| Regulatory update (a new deadline, a law entering into force, a new jurisdiction) | The primary source (official journal, statute site, regulator page) with a link and the date you checked it. Secondary sources (law-firm notes, blogs) are welcome as pointers but not as the only source. Use the "Regulatory update" issue template |
| Standards update (new OWASP edition, CVSS/EPSS change, revoked directive) | Link to the issuing body's page; update `skills/assess/references/standards.md` and the module that cites it |
| New check in a module | The weakness (CWE), the standard requirement it maps to, a benign way to confirm it, and a copy-paste remediation |
| Bug in the hooks or scripts | A failing test in `tests/run_tests.py`, then the fix |
| Support for another assistant | Setup steps you have tested, added to `docs/OTHER-ASSISTANTS.md` |

## Rules

- Keep the project defensive: no exploit code, malware, persistence or evasion techniques,
  and nothing that weakens the authorization gate or the scope guard.
- Standard library only for the hooks and scripts (Python 3.9+), so users need no packages.
- Regulatory files flag obligations; they never state that a notification *is* required.
  Keep the two tiers (`may_trigger_now`, `readiness`) and `decided_by: client/counsel`.
- Every changed fact gets a check date. When you change a regulatory file, update its
  "Checked" line and the "Regulatory data checked" date in `regulatory/index.md`.
- No personal or client data in examples: use `example.com`/`example.nl` hosts, fictitious
  organizations and documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).

## Before you open a pull request

```bash
python3 tests/run_tests.py        # all tests must pass
python3 tools/release_check.py    # no personal data, secrets or version drift
claude plugin validate .claude-plugin/plugin.json   # if you have Claude Code
```

Bump the version only in release pull requests (maintainers): `.claude-plugin/plugin.json`,
`.claude-plugin/marketplace.json`, every `skills/*/SKILL.md` `metadata.version`, and a new
`CHANGELOG.md` entry. `tools/release_check.py` fails if they disagree.

By contributing you agree that your contribution is licensed under the Apache License 2.0
(section 5 of the license).
