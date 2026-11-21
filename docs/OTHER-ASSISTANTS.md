# Using appaudit with other AI assistants

appaudit is built for Claude, where the plugin adds enforcement (scope guard, evidence log,
parallel reviewer agents, an independent verifier). The assessment knowledge itself is plain
Markdown, so it also runs in other assistants, with fewer guarantees.

## Which package to use

| Assistant | Package | What you get | What you lose |
|-----------|---------|--------------|---------------|
| Claude Code, Cowork | `appaudit-<v>.plugin` | Everything | — |
| claude.ai (web, desktop, mobile) | `appaudit-skill-<v>.zip` | Full playbook; scripts run in Claude's code sandbox | Hooks (no scope guard, no evidence log), sub-agents |
| OpenAI Codex, Gemini CLI, GitHub Copilot, Cursor, other SKILL.md readers | `appaudit-skill-<v>.zip` | Full playbook; scripts run in the tool's terminal | Hooks, sub-agents (the single-agent workflow applies) |
| ChatGPT (Custom GPT or Project), ChatGPT skills where enabled | `appaudit-portable-<v>.zip` (or the skill zip where skills are available) | Playbook as knowledge files; scripts via code execution, if enabled | Hooks, sub-agents, automatic module loading |
| Google Gemini (Gems; Gemini app skills where rolled out) | `appaudit-portable-<v>.zip` (or the skill zip for skills) | Playbook as knowledge files | Hooks, sub-agents, scripts (no code execution on uploaded files in Gems) |
| xAI Grok (Projects / custom instructions) | `appaudit-portable-<v>.zip` | Playbook as knowledge files | Hooks, sub-agents, scripts |
| Any API (Anthropic, OpenAI, Google, xAI, open models) | `appaudit-portable-<v>.zip` | System prompt + files you place in context or retrieval | Whatever your own harness does not implement |

Product limits change; the figures below were checked in November 2026. If a limit has
changed, the rule stays the same: the system prompt goes into the instructions field, the
knowledge files into the files/knowledge section.

## ChatGPT

**Custom GPT** (Explore GPTs → Create → Configure):

1. *Instructions*: paste `SYSTEM-PROMPT.md` (about 3,000 characters; the field holds 8,000).
2. *Knowledge*: upload the 10 files from `knowledge/` (the limit is 20 files).
3. *Capabilities*: turn on **Code Interpreter & Data Analysis** if you want SARIF, the .xlsx
   register and the evidence bundle; then also upload the files from `scripts/`.
4. *Capabilities*: turn on **Web Search** for the update check and KEV/EPSS lookups.
5. Keep the GPT private unless you mean to share it; never upload client evidence to a
   shared GPT.

**ChatGPT Project**: put `SYSTEM-PROMPT.md` into the project instructions and add the
knowledge files to the project files. Where your workspace has skills enabled, upload the
skill zip instead.

## Google Gemini

**Gem** (Gems manager → New Gem):

1. *Instructions*: paste `SYSTEM-PROMPT.md` (about 3,000 characters; keep it under 4,000).
2. *Knowledge*: add the 10 files from `knowledge/` (the limit is 10 files).
3. Gems cannot run the Python scripts. Ask for `findings.json`, the brief and the report, and
   run `build_outputs.py` yourself on a computer with Python 3.9+ for the other outputs.

**Gemini app skills / Gemini CLI**: use the skill zip (`appaudit/` folder). In Gemini CLI put
it in `~/.gemini/skills/` or the project's `.gemini/skills/`; the CLI asks before a skill
activates.

## xAI Grok

Create a **Project**, paste `SYSTEM-PROMPT.md` into its instructions and attach the
knowledge files. Grok does not run the scripts; build the file outputs yourself as for Gemini.

## OpenAI Codex, GitHub Copilot, Cursor and other agentic coding tools

These read the Agent Skills format directly. Unzip `appaudit-skill-<v>.zip` into the tool's
skills folder (see the README inside the zip). They have a terminal, so the update check, the
builder and the other scripts run as documented. They have no appaudit hooks: before any
active test, restrict network access yourself (sandbox, firewall or the tool's own approval
settings) and keep the authorization record outside the repository.

## Running the scripts yourself

```bash
python3 scripts/check_update.py                       # first step of every assessment
python3 scripts/merge_candidates.py --findings findings.json --candidates pass-*.json
python3 scripts/build_outputs.py --findings findings.json --out reports
python3 scripts/compare_runs.py --previous old/findings.json --current new/findings.json
python3 scripts/scan_extension.py ./some-plugin.zip --name some-plugin --unpack ./review-copy
python3 scripts/scan_extension.py --discover            # where plugins, skills and MCP configs live here
```

## Reviewing plugins, skills and MCP servers with another assistant

The extension checklist is in knowledge file `06-ai-agent.md` (second part) and in the skill's
`references/module-agent-extensions.md`.

| Assistant | How |
|-----------|-----|
| Codex, Gemini CLI, Copilot, Cursor (terminal) | Ask for an extension review; the skill runs `scan_extension.py`, then works through the checklist itself |
| ChatGPT with code execution | Upload the extension archive and `scripts/scan_extension.py`; ask it to run the scan, then review |
| Gemini Gems, Grok, ChatGPT without code execution | Run `scan_extension.py` on your computer; upload `capabilities.md`, `candidates.json` and the extension's text files; ask for a review with the agent-extensions module |

Invisible characters may not survive an upload or a chat window, which is one more reason to run
the scanner locally. Never install the extension before the review, and never in the same
environment that holds client data.

Standard library only; Python 3.9 or newer.

## Differences you must compensate for

| Plugin feature | Without it, do this |
|----------------|---------------------|
| Scope guard blocks out-of-scope hosts | Review every command before it runs; prefer static review; use OS-level egress rules for active tests |
| Hash-chained evidence log | Keep your own request/response log; store it with access control; the bundle then has no verified chain |
| Parallel reviewer agents | Ask for one module pass at a time ("now the API pass"), then a merge |
| Independent verifier agent | Start a fresh chat, paste only the findings and evidence, and ask it to check them sceptically; the report says "self-verified" otherwise |
| Regulatory mapper agent | Ask for the regulatory pass separately, after the findings are final |
| Output builder | Run `build_outputs.py` yourself, or accept Markdown brief and report only |

The outputs are the same format everywhere, so a report started in one assistant can be
finished, re-tested or compared in another.
