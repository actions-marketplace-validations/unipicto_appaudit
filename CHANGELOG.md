# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org/).
The plugin, its skills and the standalone skill share one version number from 4.2.0 on.

## [4.4.0] - 2026-11-22

Result of a critical pre-publication review. First version published on GitHub.

### Fixed
- **Scope guard blind spots.** During an open engagement the guard let through an out-of-scope
  host given to a program it did not know (`python3 scan.py host`, `docker run … -u host`,
  `npx tool host`), targets read from a list file (`nmap -iL`, `wget -i`, `sqlmap -r`), SSH
  aliases, and commands built at run time (`… | base64 -d | sh`, `eval`). It now asks the user in
  these cases and checks readable target lists host by host. `curl --resolve` / `--connect-to`
  and a `Host:` header that point an in-scope name elsewhere are denied.
- **Fail-open without Python.** If neither `python3` nor `python` was found, the guard did not
  run at all. While an engagement file exists, every tool call now asks the user instead.
- Scope and evidence files named without their folder (`cd .appaudit && … > scope.json`) now
  need approval like any other change to them.
- Documentation no longer calls the evidence log tamper-evident without qualification: the chain
  shows later edits, but the whole chain can be rebuilt by someone who can write the file.
- The project's own CI pinned no actions, against its own guidance. All actions are pinned by
  commit SHA; Dependabot keeps them current.

### Added
- **Scanner gate**: with no engagement open, starting a scanning or attack tool (nmap, sqlmap,
  nuclei and similar) asks first. Plugin option `scanner_gate`: `ask` (default), `deny`, `off`.
- **Tool-description poisoning** (EXT-M08): instruction-style text inside code, where MCP tool
  descriptions live; the override, concealment, exfiltration and remote-instruction rules also
  run on code strings. **Look-alike letters** (EXT-I17): words mixing Latin with Cyrillic or Greek.
- `scan_extension.py` writes `candidates.sarif` (SARIF 2.1.0) and accepts `--ignore-file`
  (accepted candidates with a mandatory reason, reported, never dropped silently).
- **GitHub Action** (`uses: unipicto/appaudit@v4`): extension scan in CI with the capabilities
  report in the job summary, a severity gate and SARIF output. appaudit's CI scans its own
  repository with it.
- Evidence anchoring: `verify_evidence.py --expect-head`; closing an engagement tells the user to
  send the head hash to the client.
- Release packages carry signed build provenance (`gh attestation verify`).
- `docs/THREAT-MODEL.md` (what appaudit protects against, what it does not, known bypasses) and
  diagrams in `docs/assets/`.

### Changed
- Tested on Python 3.9 and 3.13 (was 3.8 and 3.13).

## [4.3.2] - 2026-11-21

### Fixed
- Plugin description was 537 characters; saving the plugin in claude.ai or Cowork requires at most
  500. The plugin and marketplace descriptions are now 368 characters.
- Removed the undocumented `network` field from `plugin.json` (not read by any appaudit code; Claude
  strips unknown top-level fields and stricter validators may reject them).

### Added
- EXT-P08 also flags plugin and marketplace-entry descriptions over 500 characters; the release check
  and the tests enforce the same limit on appaudit's own manifests.

## [4.3.1] - 2026-11-21

### Fixed
- The `assess` skill description was 1,027 characters; Claude accepts at most 1,024, so uploading
  the plugin or skill to claude.ai or Cowork failed validation. Descriptions are now 886
  (`assess`) and 668 (`extension`) characters.
- Wording: descriptions no longer start with "Authorized", which could read as if appaudit or its
  results were approved or certified by someone. They now say what was meant: for systems the user
  owns or has the owner's written permission to test. README, user manual and `assess` explain that
  "authorization" in appaudit means that permission, recorded by the user and not granted, verified
  or certified by appaudit. The brief and report label it "Permission to test (declared by the
  assessor, not verified by appaudit)".

### Added
- Rule EXT-P08: skill metadata that Claude rejects on upload (name and description limits). The
  release check and the test suite apply the same limits to appaudit's own skills, including the
  renamed standalone skill.

## [4.3.0] - 2026-11-20

### Added
- **Extension review** (`/appaudit:extension`): checks AI-agent extensions before they are
  installed or updated — Claude Code and Cowork plugins and marketplaces, Agent Skills, subagents,
  commands, hooks, MCP servers and MCP configuration files (Claude Code, Claude Desktop, Cursor,
  VS Code, Windsurf, Gemini CLI, Codex), MCP bundles, Gemini CLI extensions, rules files
  (CLAUDE.md, AGENTS.md, GEMINI.md, Cursor, Copilot, Windsurf, Cline), browser extensions and GPT
  Action schemas.
- `scan_extension.py`: offline, deterministic scanner that never executes, imports, installs or
  downloads anything from the target. Inventory with SHA-256 per file and a package digest;
  "What this extension can do" capabilities table; 61 rules (EXT-I instructions, EXT-C code,
  EXT-H hooks, EXT-M MCP, EXT-S settings, EXT-P package, EXT-B browser, EXT-G actions, EXT-D drift);
  invisible-Unicode detection with decoding of hidden tag text; checks for documented scanner-bypass
  techniques (padding, compiled bytecode, office documents and nested archives, persuasive text aimed
  at reviewers); `--baseline` drift review of updates; `--discover` for installed extensions;
  `--unpack` for a safe review copy; `--fail-on` for CI gates.
- `extension-reviewer` agent (read-only): purpose fit, plain-language intent, toxic combinations,
  and a verdict on each scanner candidate; hardened against text in the package that addresses it.
- `module-agent-extensions.md`: checklist (instruction integrity, code behaviour, MCP, settings,
  browser extensions, provenance and update drift), validation and scoring guidance, install-decision
  rules and the full rule catalogue; included in the portable bundle (knowledge file 06).
- Install decision in findings (`summary.install_decision`: do_not_install /
  install_with_conditions / no_blocking_issue_found), printed at the top of the brief.
- `build_outputs.py --attach` adds supporting files (capabilities table, inventory) to the run
  folder, the evidence bundle and the manifest. `merge_candidates.py --engagement` starts a findings
  file from a given engagement block. New authorization basis `obtained-copy` for static review of
  a distributed artifact.
- Release gate: the build scans its own plugin and skill packages with `scan_extension.py` and
  stops on any Low-or-higher candidate (OWASP AST08).
- `docs/COVERAGE-GUIDE.md`: every product type — what is checked, what to provide, how to start,
  what is left to you — with extension reviews in detail.

### Changed
- Six parallel reviewer agents (was five). Documentation, manifests and the portable system prompt
  describe extension reviews.

## [4.2.0] - 2026-11-20

First public release on GitHub (Apache License 2.0).

### Added
- **Update check as the first step** of every assessment: `check_update.py` compares the
  installed version with the published `plugin.json` on GitHub and reports the result as the
  first line; the assessment continues either way and nothing is installed. The output builder
  reuses the saved result (no second network call). Plugin option `update_source` (default:
  this repository; `off` disables it).
- **Wave 2 jurisdictions**: Singapore (PDPA, Cybersecurity Act incl. 2025 amendments, MAS TRM
  Notices, CLS), Japan (APPI and its 2026 amendment, Active Cyber Defense law in force since
  1 Oct 2026, JC-STAR, IPA/JPCERT disclosure) and India (CERT-In 6-hour reporting, DPDP Rules
  2025 as readiness from 13 May 2027, RBI, SEBI CSCRF, IRDAI). Testing-law and disclosure
  tables extended; new regulatory roles.
- **Multi-agent workflow**: five read-only domain reviewer agents (web, API and supply chain,
  mobile, firmware, AI agents) that run in parallel; `merge_candidates.py` de-duplicates their
  candidates by root cause and assigns IDs; a `regulatory-mapper` agent proposes two-tier flags;
  the existing independent `verifier` checks every finding. Single-agent fallback documented for
  claude.ai and other assistants.
- **Re-test comparison**: `/appaudit:retest` skill and `compare_runs.py` (fixed, new,
  persisting with severity/SSVC changes, risk-accepted, not re-tested; regulatory flag changes);
  `build_outputs.py --previous` adds `delta.md` / `delta.json` and a re-test line to the brief.
- Automatic jurisdiction coverage: the builder lists every profile jurisdiction this version
  does not cover under "Jurisdictions not assessed" (China as "warnings only").
- `findings.schema.json` (JSON Schema 2020-12) for `findings.json`.
- Packages for other assistants: standalone Agent Skill (claude.ai, OpenAI Codex, Gemini CLI,
  GitHub Copilot, Cursor and other SKILL.md readers) and a portable bundle for ChatGPT, Gemini
  and Grok (system prompt under 4,000 characters, 10 knowledge files, optional scripts).
- Repository tooling: test suite, `release_check.py` (personal data, secrets, version drift),
  reproducible `build_dist.py`, CI on Linux/Windows/macOS, tag-driven release workflow, example
  workflow for uploading `findings.sarif` to GitHub code scanning.
- Documentation: README, user manual, how-it-works, other-assistants guide, publishing guide,
  security policy, contributing guide.

### Changed
- One version number for plugin and skills (4.2.0); the plugin was 0.2.0, the skill 4.1.0.
- Project-specific references replaced by a generic "Organization reference documents" section.
- Scope guard: trusted plugin scripts are recognised with Windows paths and line continuations;
  `merge_candidates.py` and `compare_runs.py` added to the trusted set.

## [4.1.0] - 2026-11-19 (skill) / [0.2.0] (plugin)

- Regulatory layer for EU, NL, US federal + New York, UK, Canada and Australia, with China
  testing-law and disclosure warnings; two-tier flags.
- Six outputs every run from one `findings.json`: brief, report, findings.json, SARIF 2.1.0,
  findings register (.xlsx), evidence bundle with SHA-256 manifest; update check (report only).
- Scope skill collects a jurisdiction profile and applies a testing-law gate.

## [4.0.0] - 2026-11-19 (skill) / [0.1.0] (plugin)

- Renamed to appaudit. First plugin: scope guard, hash-chained evidence log, verifier agent,
  scope / intel / report skills.

## [3.x] - 2026-11-18

- Router plus modules (web, API/supply chain, mobile, hardware/firmware, AI agents), CVSS v4.0
  + SSVC + EPSS + KEV scoring, standards verified against issuing bodies, `vuln_intel.py`.
