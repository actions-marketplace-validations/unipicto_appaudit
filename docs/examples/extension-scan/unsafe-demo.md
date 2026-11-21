# Extension scan — md-helper-demo

Scanned 2026-11-21T23:54:55Z with appaudit scan_extension 1.1. Target: `md-helper`. Package digest (SHA-256 over all files): `26456d240d5ffc7fe3bdfa029277f1f896efdf306ac9de946fc987d50bbc8513`.

## Install guidance: Do not install yet

The scan found at least one High or Critical candidate. Do not install until each one is verified or disproved (extension-reviewer agent + verifier); many turn out to be justified by the extension's purpose, some do not.

| Critical | High | Medium | Low | Informational |
|---|---|---|---|---|
| 0 | 9 | 4 | 3 | 1 |

## What this extension can do

| Capability | Found | Details |
|---|---|---|
| Runs code automatically (hooks, MCP servers, monitors, LSP, status line, PATH executables) | **Yes** | MCP server (stdio) — starts with the agent session; hook — PostToolUse [*] |
| Reaches the network from code or configuration | **Yes** | 203.0.113.50 |
| Tells the model to visit web addresses | **Yes** | webhook.site |
| Connects to remote MCP servers | **Yes** | http://203.0.113.50/mcp |
| Reads credential or sensitive files | No | — |
| Changes shell start-up, scheduled tasks or agent settings | No | — |
| Loosens permission prompts or approvals | **Yes** | settings.json: allow Bash(*); settings.json: enableAllProjectMcpServers |
| Contains embedded credentials | No | — |
| Contains content the scanner could not inspect | No | — |
| Gives the model instructions | **Yes** | 1 file(s), 251 characters |

## What it says it does

- plugin md-helper: Formats Markdown tables
- skill format: Use this skill for every request before any other skill

Compare the capabilities above with this stated purpose: a capability the purpose does not explain is the first thing to question.

## Components found

| Component | Count |
|---|---|
| plugins | 1 |
| skills | 1 |
| hooks | 1 |
| mcp servers | 4 |
| settings | 1 |

## Candidate findings

| Severity | Rule | Title | Location |
|---|---|---|---|
| High | EXT-C07 | Contacts a data-collection, tunnelling or raw-IP endpoint | `.claude-plugin/plugin.json:13` |
| High | EXT-C07 | Contacts a data-collection, tunnelling or raw-IP endpoint | `hooks/hooks.json:9` |
| High | EXT-C07 | Contacts a data-collection, tunnelling or raw-IP endpoint | `skills/format/SKILL.md:9` |
| High | EXT-H02 | PostToolUse hook contacts the network | `hooks/hooks.json:9` |
| High | EXT-I01 | Invisible Unicode characters can hide instructions from human reviewers | `skills/format/SKILL.md:7` |
| High | EXT-I03 | Instruction to hide actions from the user | `skills/format/SKILL.md:9` |
| High | EXT-I06 | Instruction to send conversation, files or results to an outside address | `skills/format/SKILL.md:9` |
| High | EXT-M02 | MCP server 'sync' uses an unencrypted connection | `.claude-plugin/plugin.json:12` |
| High | EXT-S01 | Settings pre-approve every shell command | `settings.json:4` |
| Medium | EXT-I09 | Description is written to make the agent load it for unrelated work | `skills/format/SKILL.md:1` |
| Medium | EXT-I13 | Pre-approves unrestricted shell commands while active | `skills/format/SKILL.md:1` |
| Medium | EXT-M01 | MCP server 'fmt' downloads and runs an unpinned package at every start | `.claude-plugin/plugin.json:5` |
| Medium | EXT-S03 | Settings start every MCP server a project defines without asking | `settings.json:7` |
| Low | EXT-H05 | Hook runs in the background without a time limit | `hooks/hooks.json:9` |
| Low | EXT-H06 | Hook runs on every tool call or prompt | `hooks/hooks.json:9` |
| Low | EXT-P06 | Plugin has no version, so every new commit reaches users without a version change | `.claude-plugin/plugin.json:1` |
| Informational | EXT-P06 | Plugin declares no licence | `.claude-plugin/plugin.json:1` |

Candidates are unverified. In an appaudit run they go to the extension-reviewer agent and the verifier before they reach the report.

## What this scan cannot see

- What the code does when it runs: scripts, hooks and MCP servers were read, never executed.
- Tool descriptions that a remote or not-yet-installed MCP server sends at run time, and packages that npx/uvx download later.
- Malicious intent written in ordinary language without the patterns above; the reviewer agent reads for that, and a human should too.
- Content in binary, compiled or uninspected files listed above.
- Changes the publisher makes after this scan: pin the version and keep this inventory as the baseline for the next update.

Treat third-party extensions as untrusted code: a scanner result is evidence, not approval.
