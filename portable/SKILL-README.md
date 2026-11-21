# appaudit {{VERSION}} — standalone Agent Skill

This folder is the appaudit assessment skill on its own, in the open Agent Skills format
(`SKILL.md` + `references/` + `scripts/`). It works in any tool that reads SKILL.md folders.
It does **not** include the plugin's enforcement (scope guard hooks, evidence log, reviewer
and verifier agents): apply the authorization gate and guardrails in `SKILL.md` yourself.
For enforcement in Claude Code or Cowork, install the plugin instead (not both).

| Tool | Where to put this folder |
|------|--------------------------|
| claude.ai (Settings → Capabilities → Skills) | Upload the zip as it is |
| Claude Code | `~/.claude/skills/appaudit/` (personal) or `<repo>/.claude/skills/appaudit/` |
| OpenAI Codex | `~/.codex/skills/appaudit/` or `<repo>/.agents/skills/appaudit/` |
| Gemini CLI | `~/.gemini/skills/appaudit/` or `<repo>/.gemini/skills/appaudit/` |
| GitHub Copilot (VS Code, CLI, coding agent) | `<repo>/.github/skills/appaudit/` |
| Cursor and other SKILL.md readers | The tool's skills folder, or `<repo>/.agents/skills/appaudit/` |

Folder names differ between tools and change over time; check your tool's documentation.

To review a plugin, skill, MCP server or rules file before installing it, run
`scripts/scan_extension.py <copy>` and follow `references/module-agent-extensions.md` §M.

Every assessment starts with the update check (`scripts/check_update.py`) against
https://github.com/unipicto/appaudit. Full manual: https://github.com/unipicto/appaudit/blob/main/docs/USER-MANUAL.md

Licensed under the Apache License 2.0 (see LICENSE and NOTICE).
