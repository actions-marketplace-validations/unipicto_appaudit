# Extension scan — appaudit

Scanned 2026-11-22T00:55:47Z with appaudit scan_extension 1.1. Target: `appaudit-4.4.2.plugin`. Package digest (SHA-256 over all files): `5101ebdbb7aecaef64a922f0d956761de60b7de626d8838343abf9a138b38d83`.

## Install guidance: No blocking issue found by the static scan

This is not proof that the extension is safe: see 'What this scan cannot see' below.

| Critical | High | Medium | Low | Informational |
|---|---|---|---|---|
| 0 | 0 | 0 | 0 | 4 |

## What this extension can do

| Capability | Found | Details |
|---|---|---|
| Runs code automatically (hooks, MCP servers, monitors, LSP, status line, PATH executables) | **Yes** | hook — PostToolUse [^(Bash/WebFetch/mcp__.*)$]; hook — PreToolUse [^(Bash/WebFetch/Write/Edit/MultiEdit/NotebookEdit/mcp__.*)$]; hook — SessionStart |
| Reaches the network from code or configuration | **Yes** | api.first.org, github.com, json.schemastore.org, nvd.nist.gov, raw.githubusercontent.com, services.nvd.nist.gov, staging.example.nl, www.cisa.gov |
| Tells the model to visit web addresses | **Yes** | api.first.org, api.github.com, api.osv.dev, euvd.enisa.europa.eu, github.com, nvd.nist.gov, raw.githubusercontent.com, services.nvd.nist.gov, www.cisa.gov |
| Connects to remote MCP servers | No | — |
| Reads credential or sensitive files | No | — |
| Changes shell start-up, scheduled tasks or agent settings | No | — |
| Loosens permission prompts or approvals | No | — |
| Contains embedded credentials | No | — |
| Contains content the scanner could not inspect | No | — |
| Gives the model instructions | **Yes** | 36 file(s), 209,410 characters |

## What it says it does

- plugin appaudit: Non-destructive security assessments for systems you own or have the owner's written permission to test: web apps, APIs, mobile/IoT apps, firmware, AI agents, and plugins, skills and MCP servers befor
- agent ai-agent-reviewer: Use this agent during an appaudit assessment to review LLM features, AI agents, MCP servers, prompts and agent skills statically and return candidate findings. It works read-only against the files it 
- agent api-supply-chain-reviewer: Use this agent during an appaudit assessment to review APIs, dependencies, secrets, CI/CD and infrastructure-as-code statically and return candidate findings. It works read-only against the files it i
- agent extension-reviewer: Use this agent during an appaudit extension review to read an AI-agent extension (Claude Code or Cowork plugin, Agent Skill, subagent, command, hook, MCP server or MCP configuration, rules file such a
- agent firmware-reviewer: Use this agent during an appaudit assessment to review embedded firmware images and hardware design documents statically and return candidate findings. It works read-only against the files it is given
- agent mobile-reviewer: Use this agent during an appaudit assessment to review iOS, Android and smart-device companion apps statically and return candidate findings. It works read-only against the files it is given, applies 
- agent regulatory-mapper: Use this agent at the end of an appaudit assessment to map verified findings to the regulatory obligations they may trigger, using the client's jurisdiction profile and the appaudit regulatory files. 
- agent verifier: Use this agent to independently re-check security findings from an appaudit assessment before they are reported. It reads the cited code, configuration and evidence-log records, checks each claim and 
- agent web-reviewer: Use this agent during an appaudit assessment to review web applications and front-end code statically and return candidate findings. It works read-only against the files it is given, applies the appau
- skill assess: Non-destructive security assessment of web apps, APIs, mobile and smart-device apps, embedded firmware, AI/LLM agents and AI-agent extensions (plugins, skills, MCP servers, rules files, browser extens
- skill extension: Reviews an AI-agent extension before it is installed or updated: Claude Code and Cowork plugins, Agent Skills, subagents, commands, hooks, MCP servers and MCP configuration files, rules files (CLAUDE.
- skill intel: Looks up CISA KEV status, FIRST EPSS v4 and NVD CVSS data for CVE IDs and returns a table with pre-filled CVSS v4.0 verification links. This skill should be used when the user runs /appaudit:intel, as

Compare the capabilities above with this stated purpose: a capability the purpose does not explain is the first thing to question.

## Components found

| Component | Count |
|---|---|
| plugins | 1 |
| marketplaces | 1 |
| skills | 6 |
| agents | 8 |
| hooks | 3 |

## Candidate findings

| Severity | Rule | Title | Location |
|---|---|---|---|
| Informational | EXT-C01 | Detection pattern that resembles risky code (regular-expression definition) | `skills/assess/scripts/scan_extension.py:129` |
| Informational | EXT-C02 | Detection pattern that resembles risky code (regular-expression definition) | `hooks/appaudit_common.py:388` |
| Informational | EXT-C02 | Detection pattern that resembles risky code (regular-expression definition) | `skills/assess/scripts/scan_extension.py:129` |
| Informational | EXT-C09 | Detection pattern that resembles risky code (regular-expression definition) | `skills/assess/scripts/scan_extension.py:180` |

Candidates are unverified. In an appaudit run they go to the extension-reviewer agent and the verifier before they reach the report.

## What this scan cannot see

- What the code does when it runs: scripts, hooks and MCP servers were read, never executed.
- Tool descriptions that a remote or not-yet-installed MCP server sends at run time, and packages that npx/uvx download later.
- Malicious intent written in ordinary language without the patterns above; the reviewer agent reads for that, and a human should too.
- Content in binary, compiled or uninspected files listed above.
- Changes the publisher makes after this scan: pin the version and keep this inventory as the baseline for the next update.

Treat third-party extensions as untrusted code: a scanner result is evidence, not approval.
