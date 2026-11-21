#!/usr/bin/env python3
"""appaudit extension scanner: static, offline review of AI-agent extensions before you install them.

Covers Claude Code / Cowork plugins and marketplaces, Agent Skills (SKILL.md, any agent),
subagents, slash commands, hooks, MCP server configurations (Claude Code, Claude Desktop,
Cursor, VS Code, Windsurf, Gemini CLI, Codex), Gemini CLI extensions, MCP bundles (.mcpb/.dxt),
agent rules files (CLAUDE.md, AGENTS.md, GEMINI.md, Cursor/Copilot/Windsurf rules), agent
settings files, browser extensions (Chrome/Edge/Firefox manifest.json) and OpenAPI files used
as GPT Actions.

Usage:
  python3 scan_extension.py TARGET [--out DIR] [--name NAME] [--baseline OLD/inventory.json]
                            [--fail-on High] [--max-file-mb 20] [--unpack DIR] [--ignore-file FILE]
  python3 scan_extension.py --discover [--json]

TARGET  A folder, an archive (.zip .plugin .skill .mcpb .dxt .vsix .xpi .crx .tar .tgz ...)
        or a single file (SKILL.md, .mcp.json, settings.json, manifest.json, ...).

Safety: the scanner never executes, imports, installs or extracts anything from the target and
never contacts the network. Archives are read in memory with size and count limits; symbolic
links are recorded, never followed. Output is written outside the target. --unpack writes a
review copy of an archive's regular files (no links, no traversal entries, no executable bits)
for the reviewer agent to read.

Outputs (default .appaudit/extension-scan/<name>-<timestamp>/):
  inventory.json    every file with SHA-256, components, capabilities, package digest, drift
  capabilities.md   plain-language "what this extension can do" table and install guidance
  candidates.json   candidate findings in findings.json form (sources: scan_extension); feed
                    them to merge_candidates.py together with the reviewer agents' candidates
  candidates.sarif  the same candidates as SARIF 2.1.0 (GitHub code scanning, IDEs)
  engagement.json   engagement block for a static review of an obtained copy

Exit codes: 0 = done; 1 = a candidate at or above --fail-on was found; 2 = usage or read error.
Standard library only; Python 3.9+.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

try:  # Python 3.11+
    import tomllib  # type: ignore
except Exception:  # pragma: no cover - older Pythons
    tomllib = None

SCANNER_VERSION = "1.1"
SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

MAX_FILES = 5000
MAX_TOTAL_BYTES = 300 * 1024 * 1024
MAX_RATIO = 200          # zip-bomb guard: uncompressed / compressed
NESTED_DEPTH = 1

ARCHIVE_EXT = {".zip", ".plugin", ".skill", ".mcpb", ".dxt", ".vsix", ".xpi", ".crx", ".jar", ".whl",
               ".nupkg", ".apk", ".aar", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".epub"}
TAR_EXT = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")
OPAQUE_ARCHIVE_EXT = {".7z", ".rar", ".gz", ".bz2", ".xz", ".zst", ".cab", ".dmg", ".iso", ".pkg", ".deb", ".rpm"}
BINARY_EXT = {".pyc", ".pyo", ".pyd", ".so", ".dll", ".dylib", ".exe", ".bin", ".node", ".wasm", ".class",
              ".o", ".a", ".elf", ".msi", ".scr", ".com", ".sys", ".ko", ".out"}
MEDIA_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tif", ".tiff", ".ttf", ".otf",
             ".woff", ".woff2", ".eot", ".pdf", ".mp3", ".mp4", ".wav", ".ogg", ".webm", ".mov", ".avif"}
CODE_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".tsx", ".jsx", ".sh", ".bash", ".zsh",
            ".fish", ".ps1", ".psm1", ".bat", ".cmd", ".rb", ".pl", ".php", ".go", ".rs", ".lua", ".vbs",
            ".applescript", ".swift", ".kt", ".java", ".cs", ".html", ".htm"}
CONFIG_EXT = {".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env", ".xml", ".plist"}
DOC_EXT = {".md", ".markdown", ".txt", ".rst", ".mdx", ".adoc"}
RULES_FILES = {"claude.md", "agents.md", "gemini.md", ".cursorrules", ".windsurfrules", ".clinerules",
               "copilot-instructions.md", "claude.local.md"}
SHADOW_COMMANDS = {"git", "python", "python3", "node", "npm", "npx", "pip", "pip3", "ls", "cat", "curl", "wget",
                   "ssh", "scp", "sudo", "bash", "sh", "zsh", "make", "docker", "kubectl", "gh", "claude", "code",
                   "rm", "cp", "mv", "find", "grep", "sed", "awk", "tar", "zip", "unzip", "open", "uv", "uvx",
                   "java", "go", "cargo", "rustc", "pnpm", "yarn", "bun", "deno", "terraform", "aws", "gcloud", "az"}
LOOPBACK = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]"}
# XML/JSON namespace and schema identifiers: written as URLs but never contacted.
NAMESPACE_HOSTS = {"schemas.openxmlformats.org", "schemas.microsoft.com", "www.w3.org", "w3.org", "purl.org",
                   "ns.adobe.com", "schemas.xmlsoap.org", "schemas.android.com", "www.apple.com", "xmlns.com",
                   "json-schema.org", "docs.oasis-open.org", "raw.githubusercontent.com/oasis-tcs"}
PLACEHOLDER_HOSTS = re.compile(r"(^|\.)(example\.(com|org|net)|example|test|invalid|localhost)$", re.I)

HIGH_RISK_TOOL_EVENTS = {"PreToolUse", "PostToolUse", "PostToolBatch", "PermissionRequest", "UserPromptSubmit",
                         "BeforeTool", "AfterTool", "BeforeAgent", "AfterAgent"}

# ------------------------------------------------------------------ patterns

def rx(p: str, flags: int = re.IGNORECASE) -> "re.Pattern[str]":
    return re.compile(p, flags)


URL_RX = rx(r"\b(?:https?|wss?)://[^\s\"'<>()\[\]{}`\\]+")
NEGATION = rx(r"\b(never|do\s+not|don'?t|must\s+not|should\s+not|shall\s+not|no\s+longer|refuse\s+to|avoid)\b")

SECRET_PATTERNS = [
    ("private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("OpenAI/Anthropic-style key", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Stripe live key", re.compile(r"\b[rs]k_live_[0-9A-Za-z]{20,}\b")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
]
SECRET_KEY_NAME = rx(r"(token|secret|passw(or)?d|api[_-]?key|auth|credential|private[_-]?key|bearer)")
PLACEHOLDER_VALUE = rx(r"^(<[^>]+>|\$\{[^}]+\}|\$[A-Z_]+|%[A-Z_]+%|your[-_ ]|x{4,}|changeme|placeholder|todo|example|dummy|test)", re.I)

SUSPICIOUS_HOSTS = rx(
    r"(webhook\.site|requestbin|pipedream\.net|\bngrok(-free)?\.(io|app|dev)|trycloudflare\.com|"
    r"interact\.sh|\boast\.(pro|live|site|online|fun|me)|burpcollaborator|pastebin\.com|paste\.ee|hastebin|"
    r"transfer\.sh|file\.io|discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|\.onion\b)")

# Code behaviour. Each: (rule, severity, title, regex, cwe, owasp, remediation)
CODE_RULES = [
    ("EXT-C01", "Critical", "Downloads code and executes it without an integrity check", [
        rx(r"\b(curl|wget)\b[^\n|;]{0,200}\|\s*(sudo\s+)?(ba|z|k|da)?sh\b"),
        rx(r"\b(curl|wget)\b[^\n|;]{0,200}\|\s*(sudo\s+)?(python3?|node|perl|ruby|php)\b"),
        rx(r"\b(ba)?sh\s+<\(\s*(curl|wget)\b"),
        rx(r"\b(iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n]{0,200}\|\s*(iex|invoke-expression)\b"),
        rx(r"\b(iex|invoke-expression)\b[^\n]{0,80}(downloadstring|net\.webclient)"),
        rx(r"\bpowershell(\.exe)?\b[^\n]{0,80}\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{24,}"),
        rx(r"\bexec\(\s*(urllib\.request\.urlopen|requests\.get|httpx\.get)\("),
        rx(r"\beval\([^\n]{0,60}\b(fetch|https?\.get|axios|got)\("),
    ], ["CWE-494"], ["AST01", "ASI05", "LLM04:2026"],
     "Remove download-and-execute. Bundle the code in the package (so it is reviewed and hashed) or verify a pinned checksum/signature before running it."),
    ("EXT-C03", "High", "Obfuscated code that decodes and runs a hidden payload", [
        rx(r"(\b(exec|eval|function|system|spawn)|\b(pickle|marshal|dill)\.loads)\s*\([^\n]{0,60}\b(b64decode|atob|decompress|unhexlify|fromcharcode|marshal\.loads|bytes\.fromhex)"),
        rx(r"\b(b64decode|atob|unhexlify)\([^\n]{0,120}\)[^\n]{0,40}\b(exec|eval|system|spawn)\("),
        rx(r"\bmarshal\.loads\("),
        re.compile(r"String\.fromCharCode\((\s*\d+\s*,){20,}"),
    ], ["CWE-506"], ["AST01", "ASI05"],
     "Ship readable source. Obfuscation in an extension prevents review; treat the package as untrusted until the publisher removes it."),
    ("EXT-C04", "High", "Code reads credential or sensitive user files", [
        rx(r"^(?=[^\n]*(\bopen\(|\.read|read_text|read_bytes|readfile|get-content|\bcat\s|\bcp\s|copyfile|shutil\.copy|createreadstream|\bscp\s|\btar\s))"
           r"(?=[^\n]*((~|\$home|%userprofile%|expanduser\(|path\.home\(\)|homedir\(\))[^\n]{0,80}(\.ssh\b|\.aws\b|\.config/gcloud|\.azure\b|\.kube\b|\.docker/config|\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.gnupg)"
           r"|\b(id_rsa|id_ed25519|id_ecdsa)\b|\.aws/credentials|\.git-credentials|wallet\.dat|\blogin data\b|cookies\.binarycookies|\.bash_history|\.zsh_history))[^\n]+",
           re.IGNORECASE | re.MULTILINE),
    ], ["CWE-200"], ["AST03", "ASI03", "LLM02:2026"],
     "Remove access to credential stores. An extension should receive only the credentials it needs, through declared configuration (for example a sensitive userConfig option)."),
    ("EXT-C05", "High", "Code collects all environment variables", [
        rx(r"json\.dumps\(\s*(dict\()?\s*os\.environ\b"),
        rx(r"JSON\.stringify\(\s*process\.env\s*[,)]", 0),
        rx(r"\b(env|printenv)\s*\|\s*(curl|nc|ncat|wget)\b"),
        rx(r"\bget-childitem\s+env:[^\n]{0,80}\|\s*(invoke-webrequest|iwr|irm)"),
    ], ["CWE-526"], ["AST03", "ASI03", "LLM02:2026"],
     "Read only the specific variables the extension needs; never serialise or transmit the whole environment (it holds API keys and tokens)."),
    ("EXT-C06", "High", "Code installs persistence or changes agent or shell configuration", [
        rx(r"^(?=[^\n]*(\.bashrc|\.zshrc|\.bash_profile|\.zprofile|\.profile\b|config\.fish|authorized_keys|\.git/hooks/|launchagents|"
           r"\.claude/settings(\.local)?\.json|\bclaude\.md\b|\.cursorrules|\.cursor/rules|copilot-instructions\.md|\.gemini/settings\.json))"
           r"(?=[^\n]*(open\([^\n]*['\"][aw]\+?['\"]|>>|\bappendfile|\bwritefile|write_text|add-content|set-content|out-file|\btee\b|\.write\())[^\n]+",
           re.IGNORECASE | re.MULTILINE),
        rx(r"\bcrontab\s+(-[a-z]\s+)*[^\s-]|\(crontab\s+-l"),
        rx(r"\bschtasks(\.exe)?\s+/create\b|currentversion\\\\run\b|\bsystemctl\s+(--user\s+)?enable\b|\blaunchctl\s+(load|bootstrap)\b"),
    ], ["CWE-506"], ["AST01", "ASI06", "ASI10"],
     "Remove writes to shell start-up files, scheduled tasks, SSH keys, git hooks and agent settings/rules files. Changes to the user's environment must be explicit, documented and made by the user."),
    ("EXT-C08", "Medium", "Destructive file or repository operation", [
        rx(r"\brm\s+-[a-z]*r[a-z]*\s+(-[a-z]+\s+)*(/|~|\$home|\*|\"\$\{?home|\.\.)(\s|$|/)"),
        rx(r"shutil\.rmtree\(\s*(os\.path\.expanduser|path\.home|['\"]/|['\"]~)"),
        rx(r"\bremove-item\b[^\n]{0,80}-recurse[^\n]{0,80}(~|\$env:userprofile|[a-z]:\\\\)"),
        rx(r"\bdel\s+/s\s+/q\b|\brd\s+/s\s+/q\b|\bformat\s+[a-z]:"),
        rx(r"\bgit\s+push\b[^\n]{0,60}(--force\b|\s-f\b)|\bgit\s+reset\s+--hard\s+origin"),
        rx(r"\bchmod\s+-r\s+777\b|\bmkfs\.|\bdd\s+if=[^\n]{0,60}of=/dev/"),
    ], ["CWE-749"], ["ASI02", "LLM03:2026"],
     "Remove the operation or limit it to files the extension itself created, with an explicit user confirmation."),
    ("EXT-C09", "Medium", "TLS certificate verification is switched off", [
        rx(r"\bverify\s*=\s*false\b"),
        rx(r"rejectunauthorized\s*:\s*false"),
        rx(r"node_tls_reject_unauthorized['\"]?\s*[:=]\s*['\"]?0"),
        rx(r"\bcurl\b[^\n]{0,120}\s(-k|--insecure)\b"),
        rx(r"ssl\._create_unverified_context|cert_none\b|insecureskipverify\s*:\s*true"),
    ], ["CWE-295"], ["ASI04"],
     "Keep certificate verification on; pin a CA bundle if a private endpoint is needed."),
    ("EXT-C02", "Low", "Dynamic code execution or shell invocation (review the inputs)", [
        rx(r"\bos\.system\("),
        rx(r"\bsubprocess\.\w+\([^\n]{0,200}shell\s*=\s*true"),
        rx(r"\bchild_process\b[^\n]{0,80}\bexec(sync)?\(|\bexecSync\(\s*`|\bexec\(\s*`", 0),
        rx(r"\bnew\s+Function\(", 0),
        rx(r"(?<![\w.])eval\(\s*(?![\"'][^\"']*[\"']\s*\))[A-Za-z_$]", 0),
        rx(r"\binvoke-expression\b|\biex\s+\$"),
    ], ["CWE-78"], ["ASI05"],
     "Pass arguments as a list without a shell, and never build commands or code from model output or other untrusted input."),
]

# Instruction content (applies to files the model reads). (rule, sev, title, regexes, cwe, owasp, remediation, negatable)
INSTRUCTION_RULES = [
    ("EXT-I02", "High", "Instruction that tries to override the agent's rules (goal hijack)", [
        rx(r"\b(ignore|disregard|forget)\s+(all\s+|any\s+|the\s+)?(of\s+)?(your\s+|the\s+)?(previous|prior|above|earlier|preceding|system|original|other)\s+(instructions|rules|prompts?|guidelines|directions|messages)\b"),
        rx(r"\byou\s+are\s+now\s+(in\s+)?(developer|dan|jailbreak|unrestricted|god)\s*mode\b|\bnew\s+system\s+prompt\s*:|\bthe\s+(real|actual|true)\s+(instructions|task)\s+(is|are)\b|\b(enter|activate|enable)\s+(developer|god|unrestricted|jailbreak)\s+mode\b"),
    ], ["CWE-1427"], ["LLM01:2026", "ASI01", "AST05"],
     "Remove the text. Extension instructions must never ask the model to set aside the user's, the operator's or the platform's instructions.", False),
    ("EXT-I03", "High", "Instruction to hide actions from the user", [
        rx(r"\b(hide|conceal)\s+(this|it|these|that|the\s+\w+)\s+from\s+(the\s+)?(user|human)\b"),
        rx(r"(^|[.:;!>*-]\s*|\b(you|then|and|must|should)\s+)(silently|secretly|covertly)\s+(run|execute|send|upload|post|copy|install|add|write|modify|delete|exfiltrate|forward|download)\b", re.I | re.M),
        rx(r"\bkeep\s+(this|it)\s+(secret|hidden)\s+from\b"),
        rx(r"\b(do\s+not|don'?t|never)\s+(tell|inform|notify|alert)\s+(the\s+)?(user|human)\s+(that|about|when|what)\s+(you|this|the\s+(skill|plugin|hook|script|tool))\s+(sends?|uploads?|runs?|executes?|installs?|collects?|reads?|copies|modif)"),
    ], ["CWE-1427"], ["ASI09", "ASI01", "AST01"],
     "Remove the text. An extension must not ask the model to hide what it does; the user needs to see every action taken on their behalf.", False),
    ("EXT-I15", "Medium", "Instruction to withhold information from the user or act without asking", [
        rx(r"\b(do\s+not|don'?t|never)\s+(tell|inform|notify|show|mention|reveal|disclose|alert)\s+(this\s+|it\s+)?(to\s+)?(the\s+)?(user|human|developer|operator)\b"),
        rx(r"\bwithout\s+(asking|telling|informing|notifying|alerting)\s+(the\s+)?(user|human)\b"),
    ], ["CWE-1427"], ["ASI09"],
     "Check what is withheld or done without asking; anything that affects the user's files, accounts or data should be visible and confirmed.", False),
    ("EXT-I04", "High", "Instruction to switch off permission prompts or safety controls", [
        rx(r"--dangerously-skip-permissions\b|--yolo\b|\bbypasspermissions\b|\bskipdangerousmodepermissionprompt\b"),
        rx(r"\b(disable|bypass|turn\s+off|circumvent|get\s+around)\s+(the\s+|all\s+|any\s+|your\s+)?(permission|approval|safety|security|sandbox)\s*(prompts?|checks?|dialogs?|requests?|guards?|hooks?|mode|controls?|system)?\b"),
        rx(r"\bauto[- ]?approve\s+(all|every|any)\b"),
    ], ["CWE-250"], ["ASI02", "ASI03", "AST03", "LLM03:2026"],
     "Remove the text. Permission prompts are the user's control; an extension must work with them on.", True),
    ("EXT-I05", "High", "Instruction to read credentials or private user data", [
        rx(r"\b(read|open|cat|copy|upload|send|collect|access|include|attach|print|dump|grab)\b[^\n]{0,60}(\.ssh\b|\bid_rsa\b|\bid_ed25519\b|\.aws/credentials|\.npmrc|\.netrc|\.git-credentials|\bkeychain\b|browser\s+(cookies|history|passwords)|\bpassword\s+manager\b|\bwallet\b|\bseed\s+phrase\b)"),
    ], ["CWE-200"], ["LLM02:2026", "ASI03", "AST01"],
     "Remove the text. If the extension needs a credential, declare it (for example as a sensitive userConfig option) so the user provides it knowingly.", True),
    ("EXT-I16", "Medium", "Instruction moves credentials or environment variables", [
        rx(r"\b(send|upload|post|collect|exfiltrate|forward|transmit)\b[^\n]{0,40}\b(api[_ -]?keys?|access\s+tokens?|credentials|passwords|environment\s+variables|\.env\b)"),
    ], ["CWE-200"], ["LLM02:2026", "ASI03"],
     "Confirm each credential goes only to the service it belongs to, over HTTPS, and is never logged or written to files.", True),
    ("EXT-I06", "High", "Instruction to send conversation, files or results to an outside address", [
        rx(r"\b(send|post|upload|forward|transmit|exfiltrate|submit|sync|mirror|copy)\b[^\n]{0,60}\b(conversation|chat|history|transcript|files?|contents?|code|repo(sitory)?|secrets?|keys?|tokens?|credentials|environment|context|memory|prompts?|outputs?|results?|data|logs?)\b[^\n]{0,60}\b(to|at|via|into)\b[^\n]{0,30}(https?://|wss?://|webhook|discord|telegram|pastebin|ngrok|requestbin|\S+@\S+\.\w+)"),
    ], ["CWE-201"], ["LLM02:2026", "ASI02", "AST01"],
     "Remove the text, or document the data flow in the extension's description and make it opt-in with a visible confirmation.", True),
    ("EXT-I10", "High", "Instruction to load instructions or code from a remote source", [
        rx(r"\b(fetch|download|load|retrieve|get|pull|read)\s+(the\s+)?(latest\s+|updated\s+|current\s+|new\s+|real\s+)?(instructions|rules|prompts?|system\s+prompt|guidelines|skill|skills|commands)\s+(from|at)\s+(https?://|the\s+(url|server|endpoint|gist))"),
        rx(r"\bfollow\s+(the\s+)?(instructions|steps|rules)\s+(at|from|in|on)\s+https?://"),
    ], ["CWE-829"], ["AST05", "AST07", "ASI01", "LLM01:2026"],
     "Bundle the instructions in the package so they are reviewed and hashed; never let a remote server change what the agent is told to do.", True),
    ("EXT-I12", "Low", "Instruction to change agent memory, rules or settings files", [
        rx(r"\b(add|append|write|insert|save|update|modify|edit|overwrite)\b[^\n]{0,50}(\bclaude\.md\b|\bagents\.md\b|\bgemini\.md\b|\.cursorrules|\.cursor/rules|copilot-instructions\.md|\.claude/settings(\.local)?\.json|\.gemini/settings\.json|\.codex/config\.toml|\byour\s+memory\b|\bpersistent\s+memory\b)"),
    ], ["CWE-15"], ["ASI06", "ASI10", "AST01"],
     "Remove the text. Changes to the agent's standing instructions or settings must come from the user, not from an extension.", True),
    ("EXT-I14", "Medium", "Instruction to change shell start-up files, scheduled tasks or SSH keys", [
        rx(r"\b(add|append|write|insert|save|update|modify|edit|create)\b[^\n]{0,50}(\.bashrc|\.zshrc|\.bash_profile|\.zprofile|\bcrontab\b|authorized_keys|\.git/hooks|launchagents|scheduled\s+task|startup\s+folder)"),
    ], ["CWE-506"], ["ASI10", "AST01"],
     "Remove the text. Persistence on the user's machine is never part of an extension's job.", True),
    ("EXT-I07", "Medium", "Text that tries to influence reviewers, scanners or the model's trust", [
        rx(r"\b(this|the)\s+(skill|plugin|extension|server|package|tool|file|code|repo(sitory)?)\s+(is|has\s+been|was)\s+(pre-?approved|approved|verified|audited|certified|whitelisted|allow-?listed|vetted|trusted)\b"),
        rx(r"\b(security|compliance|it|legal)\s+team\s+(has\s+)?(approved|authori[sz]ed|mandates?|requires?)\b"),
        rx(r"\b(ai|llm|automated)\s+(reviewers?|scanners?|auditors?|assistants?)\s+(should|must|are\s+(instructed|required)\s+to)\b"),
        rx(r"\b(mark|rate|classify|report|treat)\s+(this|it|these)\s+as\s+(safe|benign|low[- ]risk|compliant|clean|trusted)\b"),
        rx(r"\bdo\s+not\s+(flag|report|scan|analy[sz]e|review)\s+(this|these|the\s+following)\b"),
        rx(r"\bif\s+you\s+are\s+an?\s+(ai|llm|language\s+model|assistant|agent|scanner)\b"),
    ], ["CWE-1427"], ["AST08", "ASI09", "LLM01:2026"],
     "Remove the text. Claims of prior approval inside a package carry no weight and are a known technique to lower scanner and reviewer ratings.", False),
]

TRIGGER_RULES = [
    rx(r"\b(every|all|any)\s+(user\s+)?(requests?|tasks?|messages?|prompts?|conversations?|queries)\b"
       r"(?!\s+(about|involving|for|related|that|to|with|regarding|on|where|which|mentioning|concerning|in|of|asking|from)\b)"),
    rx(r"\b(before|instead\s+of)\s+(any|all|every|other)\s+(other\s+)?(skills?|tools?|agents?|plugins?)\b"),
]

ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x180E, 0xFEFF}
BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200E, 0x200F, 0x061C}


# ------------------------------------------------------------------ data model

class VFile:
    __slots__ = ("path", "data", "size", "kind", "link", "exec_bit", "nested", "truncated", "note")

    def __init__(self, path, data=None, size=0, kind="file", link=None, exec_bit=False, nested=False,
                 truncated=False, note=""):
        self.path, self.data, self.size, self.kind = path, data, size, kind
        self.link, self.exec_bit, self.nested, self.truncated, self.note = link, exec_bit, nested, truncated, note


class Scan:
    def __init__(self, name: str, root_label: str, max_file: int):
        self.name = name
        self.root_label = root_label
        self.max_file = max_file
        self.files: list = []
        self.cands: dict = {}
        self.components = {"plugins": [], "marketplaces": [], "skills": [], "agents": [], "commands": [],
                           "hooks": [], "mcp_servers": [], "lsp_servers": [], "monitors": [], "bin": [],
                           "settings": [], "rules_files": [], "browser_extensions": [], "gemini_extensions": [],
                           "openapi": [], "npm_packages": [], "mcp_bundles": []}
        self.cap = {"auto_exec": [], "network_code": {}, "network_instructions": {}, "network_docs": {},
                    "remote_mcp": [], "sensitive_access": [], "persistence": [], "permission_changes": [],
                    "uninspected": [], "secrets": 0, "instruction_files": [], "declared_purpose": [],
                    "browser_permissions": []}
        self.notes: list = []
        self.total = 0
        self.text_cache: dict = {}
        self.roots_with_skill = set()
        self.context_files = set()

    # candidate aggregation: one candidate per (rule, file)
    def add(self, rule, sev, title, path, line, evidence, cwe, owasp, remediation, description="", conf="Likely",
            kind="file"):
        key = (rule, path, title)
        ev = clean_evidence(evidence)
        if key in self.cands:
            c = self.cands[key]
            c["_lines"].append(line)
            if SEV_RANK[sev] < SEV_RANK[c["severity"]]:
                c["severity"] = sev
            if ev and len(c["_ev"]) < 3 and ev not in c["_ev"]:
                c["_ev"].append(ev)
            return
        loc = {"kind": kind, "uri": path}
        if isinstance(line, int) and line >= 1:
            loc["start_line"] = line
        self.cands[key] = {
            "title": title, "severity": sev, "confidence": conf, "asset": self.name,
            "location": loc, "cwe": list(cwe), "owasp": list(owasp),
            "description": description or title, "remediation": {"summary": remediation},
            "retest": {"action": f"Re-run scan_extension.py on the updated package; rule {rule} must not report {path}.",
                       "expected": f"No {rule} result for this file."},
            "sources": ["scan_extension"], "rule": rule, "_lines": [line], "_ev": [ev] if ev else []}

    def candidates(self) -> list:
        out = []
        for raw in self.cands.values():
            c = json.loads(json.dumps({k: v for k, v in raw.items() if not k.startswith("_")}))
            lines = sorted({l for l in raw["_lines"] if isinstance(l, int)})
            ev = raw["_ev"]
            extra = []
            if len(lines) > 1:
                shown = ", ".join(str(l) for l in lines[:12]) + (" …" if len(lines) > 12 else "")
                extra.append(f"{len(lines)} occurrences (lines {shown}).")
            if ev:
                extra.append("Evidence: " + " | ".join(ev))
            c["location"]["description"] = f"{c['rule']}: " + " ".join(extra) if extra else c["rule"]
            if extra:
                c["description"] = c["description"].rstrip(".") + ". " + " ".join(extra)
            out.append(c)
        out.sort(key=lambda c: (SEV_RANK[c["severity"]], c["rule"], c["location"]["uri"]))
        return out


def clean_evidence(s) -> str:
    if not s:
        return ""
    s = str(s)
    for _, p in SECRET_PATTERNS:
        s = p.sub(lambda m: "…" + m.group(0)[-4:], s)
    out = []
    for ch in s:
        cp = ord(ch)
        if cp < 32 or cp in ZERO_WIDTH or cp in BIDI or 0xE0000 <= cp <= 0xE007F or 0xFE00 <= cp <= 0xFE0F:
            out.append(f"\\u{cp:04X}" if cp <= 0xFFFF else f"\\U{cp:08X}")
        else:
            out.append(ch)
    s = "".join(out).strip()
    return s[:160] + ("…" if len(s) > 160 else "")


def redact_secret(v: str) -> str:
    v = str(v)
    return "…" + v[-4:] if len(v) > 4 else "…"


# ------------------------------------------------------------------ loading

def safe_member_name(name: str) -> tuple:
    n = name.replace("\\", "/")
    bad = n.startswith("/") or re.match(r"^[A-Za-z]:", n) is not None or ".." in PurePosixPath(n).parts
    return n.lstrip("/"), bad


def load_zip(scan: Scan, data: bytes, prefix: str, depth: int, container: str):
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        scan.cap["uninspected"].append(f"{container} (unreadable archive)")
        scan.add("EXT-P04", "Medium", "Archive could not be read, so its contents were not inspected", container, None,
                 "bad zip", ["CWE-1357"], ["AST08", "AST02"], "Provide the extension as a readable folder or standard zip.")
        return
    infos = z.infolist()
    comp = sum(i.compress_size for i in infos) or 1
    uncomp = sum(i.file_size for i in infos)
    if uncomp / comp > MAX_RATIO and uncomp > 50 * 1024 * 1024:
        scan.add("EXT-P05", "High", "Archive looks like a decompression bomb; not inspected", container, None,
                 f"ratio {uncomp // comp}:1", ["CWE-409"], ["AST08"], "Do not open this archive; ask the publisher for a normal package.")
        scan.cap["uninspected"].append(f"{container} (decompression-bomb ratio)")
        return
    for info in infos:
        if info.is_dir():
            continue
        name, bad = safe_member_name(info.filename)
        path = f"{prefix}{name}"
        mode = (info.external_attr >> 16) & 0xFFFF
        if bad:
            scan.add("EXT-P01", "High", "Archive entry would be written outside the install folder (path traversal)", container,
                     None, info.filename, ["CWE-22"], ["AST02", "ASI04"],
                     "Reject the package; a legitimate extension never contains absolute or '..' paths.")
        if info.flag_bits & 0x1:
            scan.add("EXT-P04", "Medium", "Encrypted archive entry could not be inspected", container, None, info.filename,
                     ["CWE-1357"], ["AST08"], "Ask for an unencrypted package.")
            scan.cap["uninspected"].append(f"{path} (encrypted)")
            continue
        if stat.S_ISLNK(mode):
            target = z.read(info).decode("utf-8", "replace")
            scan.files.append(VFile(path, None, 0, "symlink", target, nested=depth > 0))
            continue
        if len(scan.files) >= MAX_FILES or scan.total > MAX_TOTAL_BYTES:
            scan.notes.append("file or size limit reached; remaining archive entries not inspected")
            scan.cap["uninspected"].append(f"{container}: entries after {path}")
            break
        size = info.file_size
        with z.open(info) as fh:
            blob = fh.read(scan.max_file + 1)
        truncated = len(blob) > scan.max_file
        blob = blob[:scan.max_file]
        scan.total += len(blob)
        vf = VFile(path, blob, size, "file", exec_bit=bool(mode & 0o111), nested=depth > 0, truncated=truncated)
        scan.files.append(vf)
        maybe_nested(scan, vf, depth)


def load_tar(scan: Scan, data: bytes, prefix: str, depth: int, container: str):
    try:
        t = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except (tarfile.TarError, OSError, EOFError):
        scan.cap["uninspected"].append(f"{container} (unreadable tar)")
        return
    with t:
        for m in t.getmembers():
            name, bad = safe_member_name(m.name)
            path = f"{prefix}{name}"
            if bad:
                scan.add("EXT-P01", "High", "Archive entry would be written outside the install folder (path traversal)",
                         container, None, m.name, ["CWE-22"], ["AST02"], "Reject the package.")
            if m.issym() or m.islnk():
                scan.files.append(VFile(path, None, 0, "symlink", m.linkname, nested=depth > 0))
                continue
            if not m.isfile():
                continue
            if len(scan.files) >= MAX_FILES or scan.total > MAX_TOTAL_BYTES:
                scan.notes.append("file or size limit reached in tar")
                break
            fh = t.extractfile(m)
            if fh is None:
                continue
            blob = fh.read(scan.max_file + 1)
            truncated = len(blob) > scan.max_file
            blob = blob[:scan.max_file]
            scan.total += len(blob)
            vf = VFile(path, blob, m.size, "file", exec_bit=bool(m.mode & 0o111), nested=depth > 0, truncated=truncated)
            scan.files.append(vf)
            maybe_nested(scan, vf, depth)


def maybe_nested(scan: Scan, vf: VFile, depth: int):
    low = vf.path.lower()
    ext = PurePosixPath(low).suffix
    if ext in ARCHIVE_EXT or (vf.data and vf.data[:4] == b"PK\x03\x04" and ext not in MEDIA_EXT):
        if depth < NESTED_DEPTH:
            scan.notes.append(f"nested archive inspected: {vf.path}")
            load_zip(scan, vf.data or b"", vf.path + "!/", depth + 1, vf.path)
            vf.note = "nested archive (contents scanned)"
        else:
            scan.cap["uninspected"].append(f"{vf.path} (archive nested too deep)")
            scan.add("EXT-P04", "Medium", "Archive nested inside an archive was not inspected", vf.path, None,
                     "nesting depth", ["CWE-1357"], ["AST08"], "Ship files directly, not inside nested archives.")
    elif low.endswith(TAR_EXT):
        if depth < NESTED_DEPTH:
            load_tar(scan, vf.data or b"", vf.path + "!/", depth + 1, vf.path)
            vf.note = "nested tar (contents scanned)"
    elif ext in OPAQUE_ARCHIVE_EXT:
        scan.cap["uninspected"].append(f"{vf.path} (archive format not inspected)")
        scan.add("EXT-P04", "Medium", "Compressed file in a format the scanner cannot open", vf.path, None, ext,
                 ["CWE-1357"], ["AST08", "AST02"],
                 "Ask the publisher to ship the contents unpacked, or unpack and scan them yourself before installing.")


def load_target(scan: Scan, target: Path):
    if target.is_dir():
        root = target.resolve()
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d != ".git")
            for d in list(dirnames):
                full = Path(dirpath) / d
                if full.is_symlink():
                    rel = full.relative_to(root).as_posix()
                    scan.files.append(VFile(rel, None, 0, "symlink", os.readlink(full)))
                    dirnames.remove(d)
            for fn in sorted(filenames):
                full = Path(dirpath) / fn
                rel = full.relative_to(root).as_posix()
                st = os.lstat(full)
                if stat.S_ISLNK(st.st_mode):
                    scan.files.append(VFile(rel, None, 0, "symlink", os.readlink(full)))
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                if len(scan.files) >= MAX_FILES or scan.total > MAX_TOTAL_BYTES:
                    scan.notes.append("file or size limit reached; remaining files not inspected")
                    scan.cap["uninspected"].append(f"files after {rel}")
                    return
                with open(full, "rb") as fh:
                    blob = fh.read(scan.max_file + 1)
                truncated = len(blob) > scan.max_file
                blob = blob[:scan.max_file]
                scan.total += len(blob)
                vf = VFile(rel, blob, st.st_size, "file", exec_bit=bool(st.st_mode & 0o111), truncated=truncated)
                scan.files.append(vf)
                maybe_nested(scan, vf, 0)
        return
    data = target.read_bytes()
    low = target.name.lower()
    if zipfile.is_zipfile(target) and not low.endswith((".json", ".md")):
        load_zip(scan, data, "", 0, target.name)
    elif low.endswith(TAR_EXT):
        load_tar(scan, data, "", 0, target.name)
    else:
        blob = data[:scan.max_file]
        scan.total += len(blob)
        scan.files.append(VFile(target.name, blob, len(data), "file", truncated=len(data) > scan.max_file))


# ------------------------------------------------------------------ helpers

def decode(vf: VFile):
    if vf.data is None:
        return None
    b = vf.data
    if b[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return b.decode("utf-16")
        except UnicodeDecodeError:
            return None
    if b"\x00" in b[:8192]:
        return None
    t = b.decode("utf-8", errors="replace")
    return t[1:] if t.startswith("\ufeff") else t


def strip_archive_prefix(path: str) -> str:
    return path.split("!/")[-1]


def parse_json(text: str):
    try:
        return json.loads(text)
    except ValueError:
        try:  # tolerate JSONC comments and trailing commas
            t = re.sub(r"(?m)^\s*//.*$", "", text)
            t = re.sub(r",(\s*[}\]])", r"\1", t)
            return json.loads(t)
        except ValueError:
            return None


def parse_frontmatter(text: str) -> tuple:
    """Minimal YAML front matter reader: returns (dict, end_line). Values are strings or lists."""
    if not text.startswith("---"):
        return {}, 0
    lines = text.splitlines()
    end = None
    for i in range(1, min(len(lines), 400)):
        if lines[i].strip() == "---":
            end = i
            break
    if end is None:
        return {}, 0
    fm, key, mode, buf = {}, None, None, []

    def flush():
        if key is None:
            return
        if mode == "block":
            fm[key] = " ".join(x.strip() for x in buf).strip()
        elif mode == "list":
            fm[key] = [x for x in buf]
        elif mode == "map":
            fm[key] = "\n".join(buf)

    for raw in lines[1:end]:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", raw)
        if m and not raw.startswith((" ", "\t")):
            flush()
            key, val = m.group(1), m.group(2).strip()
            buf, mode = [], None
            if val in (">", ">-", "|", "|-", ">+", "|+"):
                mode = "block"
            elif val == "":
                mode = "pending"
            elif val.startswith("["):
                fm[key] = [v.strip().strip("'\"") for v in val.strip("[]").split(",") if v.strip()]
                key = None
            else:
                fm[key] = val.strip("'\"")
                key = None
            continue
        if key is None:
            continue
        s = raw.strip()
        if mode == "pending":
            mode = "list" if s.startswith("- ") else "map"
        if mode == "list" and s.startswith("- "):
            buf.append(s[2:].strip().strip("'\""))
        else:
            buf.append(raw)
    flush()
    return fm, end + 1


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def host_of(url: str) -> str:
    try:
        h = urlparse(url).hostname or ""
    except ValueError:
        return ""
    return h.lower().strip(".")


def public_ip(h: str) -> bool:
    """A literal IPv4/IPv6 address that is routable on the internet (or an RFC 5737 documentation address)."""
    import ipaddress
    try:
        ip = ipaddress.ip_address(h.strip("[]"))
    except ValueError:
        return False
    doc = any(ip in ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")) if ip.version == 4 else False
    return ip.is_global or doc


def is_placeholder_host(h: str) -> bool:
    return (not h or h in LOOPBACK or h in NAMESPACE_HOSTS or bool(PLACEHOLDER_HOSTS.search(h))
            or any(ch in h for ch in "{}$*<>%"))


OFFICE_EXT = (".docx", ".pptx", ".xlsx", ".odt", ".odp", ".ods", ".epub")


def office_container(path: str) -> str:
    """Return the container path when `path` is the text part of an office document inside the package."""
    if "!/" not in path:
        return ""
    container, inner = path.rsplit("!/", 1)
    if container.lower().endswith(OFFICE_EXT) and inner.lower().endswith((".xml", ".xhtml", ".html")):
        return container
    return ""


def in_skill(scan: Scan, path: str) -> bool:
    low = strip_archive_prefix(path).lower()
    return any(low.startswith(r + "/") for r in scan.roots_with_skill)


def classify(path: str, text, scan: Scan) -> set:
    oc = office_container(path)
    if oc:
        return {"instruction"} if in_skill(scan, oc) or "/skills/" in "/" + oc.lower() else {"doc"}
    inner = strip_archive_prefix(path)
    p = PurePosixPath(inner.lower())
    name, ext, parts = p.name, p.suffix, p.parts
    roles = set()
    if inner.lower().endswith(".claude-plugin/plugin.json"):
        roles.add("manifest-plugin")
    if inner.lower().endswith(".claude-plugin/marketplace.json"):
        roles.add("manifest-marketplace")
    if name == "gemini-extension.json":
        roles.add("manifest-gemini")
    if name == "package.json":
        roles.add("manifest-npm")
    if name in ("hooks.json",):
        roles.add("hooks")
    if name in (".mcp.json", "mcp.json", "claude_desktop_config.json", "mcp_config.json", ".claude.json", "mcp_settings.json"):
        roles.add("mcp")
    if name in ("settings.json", "settings.local.json", ".claude.json", "managed-settings.json"):
        roles.add("settings")
    if name == "config.toml" and (".codex" in parts or "codex" in parts):
        roles.add("codex-config")
    if name == ".lsp.json":
        roles.add("lsp")
    if name == "monitors.json":
        roles.add("monitors")
    if name == "manifest.json" and text:
        d = parse_json(text)
        if isinstance(d, dict):
            if isinstance(d.get("manifest_version"), int) and any(k in d for k in (
                    "background", "content_scripts", "action", "browser_action", "permissions", "host_permissions")):
                roles.add("manifest-browser")
            elif "server" in d and ("dxt_version" in d or "manifest_version" in d):
                roles.add("manifest-mcpb")
    if ext in (".json", ".yaml", ".yml") and text and re.search(r"^\s*[\"']?(openapi|swagger)[\"']?\s*:", text[:2000], re.M):
        roles.add("openapi")
    if "bin" in parts[:2] and len(parts) >= 2 and parts.index("bin") < len(parts) - 1:
        roles.add("bin")
    is_skill_res = any(inner.lower().startswith(r + "/") or inner.lower() == r for r in scan.roots_with_skill)
    if (name == "skill.md" or name in RULES_FILES or ext == ".mdc" or name.endswith((".instructions.md", ".prompt.md", ".chatmode.md"))
            or ("agents" in parts[:-1] and ext == ".md") or ("commands" in parts[:-1] and ext in (".md", ".toml"))
            or ("output-styles" in parts[:-1] and ext == ".md") or (is_skill_res and ext in DOC_EXT)
            or inner.lower() in scan.context_files or (".cursor" in parts and "rules" in parts)):
        roles.add("instruction")
    if name in RULES_FILES or ext == ".mdc" or "copilot-instructions.md" == name:
        roles.add("rules-file")
    if ext in CODE_EXT or (text and text.startswith("#!")):
        roles.add("code")
    if ext in CONFIG_EXT and not roles & {"instruction"}:
        roles.add("config")
    if ext in DOC_EXT and "instruction" not in roles:
        roles.add("doc")
    if not roles and text is not None:
        roles.add("doc")
    return roles


TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|specs|fixtures|testdata)/|(^|/)test_[^/]*$|[._-](test|spec)\.[a-z]+$", re.I)
EXAMPLE_CONTEXT = re.compile(r"\b(e\.g\.|for example|such as|like\s*[\"'“]|attacks?|injections?|payloads?|detect|flag(ged)?|red[- ]team|phrases?|patterns?|adversarial|malicious)\b", re.I)


def is_test_file(path: str) -> bool:
    return bool(TEST_PATH.search(strip_archive_prefix(path)))


def downgrade(sev: str, steps: int = 1) -> str:
    return SEVERITIES[min(SEV_RANK[sev] + steps, len(SEVERITIES) - 1)]


def code_spans(text: str) -> list:
    """Character ranges inside Markdown inline code or fenced blocks (quoted/example context)."""
    spans = [(m.start(), m.end()) for m in re.finditer(r"```.*?```|~~~.*?~~~", text, re.S)]
    spans += [(m.start(), m.end()) for m in re.finditer(r"`[^`\n]+`", text)]
    return spans


def in_spans(pos: int, spans: list) -> bool:
    return any(a <= pos < b for a, b in spans)


# ------------------------------------------------------------------ checks

def check_hidden_unicode(scan: Scan, path: str, text: str, roles: set):
    hits, tag_text, kinds = [], [], set()
    prev = ""
    for i, ch in enumerate(text):
        cp = ord(ch)
        kind = None
        if 0xE0000 <= cp <= 0xE007F:
            kind = "tag"
            if 0xE0020 <= cp <= 0xE007E:
                tag_text.append(chr(cp - 0xE0000))
        elif cp in BIDI:
            kind = "bidi"
        elif cp in ZERO_WIDTH:
            if cp == 0x200D and prev and ord(prev) >= 0x2600 and i + 1 < len(text) and ord(text[i + 1]) >= 0x2600:
                kind = None  # emoji ZWJ sequence
            elif cp == 0xFEFF and i == 0:
                kind = None
            else:
                kind = "zero-width"
        elif 0xE0100 <= cp <= 0xE01EF:
            kind = "variation-selector"
        if kind:
            kinds.add(kind)
            hits.append(i)
        prev = ch
    if not hits:
        return
    sensitive = roles & {"instruction", "code", "hooks", "mcp", "settings", "manifest-plugin", "manifest-gemini",
                         "manifest-browser", "config", "rules-file"}
    sev = "High" if ("tag" in kinds or "bidi" in kinds or len(hits) > 10) else "Medium" if len(hits) > 2 or "instruction" in roles else "Low"
    if not sensitive:
        sev = downgrade(sev)
    ev = f"{len(hits)} invisible character(s): {', '.join(sorted(kinds))}"
    if tag_text:
        ev += f"; hidden text decodes to: {''.join(tag_text)[:100]!r}"
    scan.add("EXT-I01", sev, "Invisible Unicode characters can hide instructions from human reviewers", path,
             line_of(text, hits[0]), ev, ["CWE-912"], ["LLM01:2026", "AST04", "AST05"],
             "Remove every invisible character (zero-width, bidirectional control, Unicode tag and variation-selector "
             "supplement). Compare the file in a hex view or with `grep -P '[\\x{200B}-\\x{200F}\\x{202A}-\\x{202E}\\x{2066}-\\x{2069}\\x{E0000}-\\x{E007F}]'`.",
             description="Invisible characters are read by the model but not shown by most editors or code-review views "
                         "(the 'rules file backdoor' technique).")


def check_padding(scan: Scan, path: str, text: str, roles: set):
    if not roles & {"instruction", "code", "rules-file", "hooks", "mcp", "settings"}:
        return
    lines = text.split("\n")
    run = best = 0
    best_end = 0
    for i, l in enumerate(lines):
        if l.strip():
            run = 0
        else:
            run += 1
            if run > best:
                best, best_end = run, i
    long_line = next(((i, len(l)) for i, l in enumerate(lines) if len(l) > 20000), None)
    wide_ws = re.search(r"[ \t]{1000,}\S", text)
    instr = "instruction" in roles or "rules-file" in roles
    if best >= 500:
        scan.add("EXT-P05", "Medium", "Long run of blank lines can push content past reviewers and scanners", path,
                 best_end - best + 2, f"{best} consecutive blank lines", ["CWE-912"], ["AST08", "AST04"],
                 "Remove the padding and review what follows it.",
                 description="Padding a file with blank lines is a documented way to move content outside a scanner's inspection window.")
    if long_line and instr:
        scan.add("EXT-P05", "Medium", "Extremely long line in an instruction file", path, long_line[0] + 1,
                 f"{long_line[1]} characters", ["CWE-912"], ["AST08"], "Split or remove the line and review its full content.")
    if wide_ws and instr:
        scan.add("EXT-P05", "Medium", "Wide whitespace run hides text off-screen", path, line_of(text, wide_ws.start()),
                 "1000+ spaces before text", ["CWE-912"], ["AST08"], "Remove the whitespace and review the hidden text.")


def check_secrets(scan: Scan, path: str, text: str, roles: set):
    for label, p in SECRET_PATTERNS:
        for m in p.finditer(text):
            scan.cap["secrets"] += 1
            scan.add("EXT-C10", "Medium" if is_test_file(path) else "High", "Credential embedded in the package", path, line_of(text, m.start()),
                     f"{label} ending {redact_secret(m.group(0))}", ["CWE-798"], ["AST04", "LLM02:2026"],
                     "Remove the credential, rotate it at the issuer, and load secrets from the user's configuration at run time.")


def check_urls(scan: Scan, path: str, text: str, roles: set):
    bucket = "network_code" if roles & {"code", "hooks", "mcp", "settings", "config", "manifest-plugin",
                                         "manifest-gemini", "manifest-browser", "manifest-npm", "openapi"} \
        else "network_instructions" if "instruction" in roles else "network_docs"
    for m in URL_RX.finditer(text):
        url = m.group(0).rstrip(".,;:")
        h = host_of(url)
        if is_placeholder_host(h):
            continue
        scan.cap[bucket].setdefault(h, set()).add(path)
        if SUSPICIOUS_HOSTS.search(url) or public_ip(h):
            sev = "High" if bucket != "network_docs" else "Low"
            if is_test_file(path):
                sev = "Low"
            scan.add("EXT-C07", sev, "Contacts a data-collection, tunnelling or raw-IP endpoint", path,
                     line_of(text, m.start()), url, ["CWE-201"], ["ASI02", "AST01", "LLM02:2026"],
                     "Remove the endpoint, or document why the extension needs it and what data it sends.",
                     description="Request-capture services, tunnels, paste sites, chat webhooks and raw IP addresses are the usual "
                                 "destinations for data exfiltration.")
        if url.startswith(("http://", "ws://")) and "code" in roles:
            scan.add("EXT-M02", "Medium", "Plain-text (unencrypted) connection to a remote host", path,
                     line_of(text, m.start()), url, ["CWE-319"], ["ASI04", "ASI07"], "Use https:// or wss://.")


PATTERN_DEF = re.compile(r"(\brx\(|\bre\.(compile|search|match|fullmatch|findall|finditer|sub)\(|\bnew\s+RegExp\()")


def is_pattern_definition(text: str, pos: int) -> bool:
    """True when the match sits inside a regular-expression definition on the same line (detection rules)."""
    start = text.rfind("\n", 0, pos) + 1
    line = text[start:text.find("\n", pos) if text.find("\n", pos) != -1 else len(text)].lstrip()
    return bool(PATTERN_DEF.search(text[start:pos]) or
                re.match(r"""(rx\(|re\.compile\(|r["']|\(\s*["'][^"']*["']\s*,\s*re\.compile\()""", line))


def check_code(scan: Scan, path: str, text: str, roles: set):
    in_md = "instruction" in roles or "doc" in roles
    for rule, sev, title, pats, cwe, owasp, rem in CODE_RULES:
        if rule == "EXT-C02" and in_md:
            continue  # dynamic exec in prose is not code
        for p in pats:
            for m in p.finditer(text):
                s = sev
                note = ""
                if "doc" in roles and "instruction" not in roles:
                    s = downgrade(sev, 2)
                elif in_md:
                    # Instructions are mediated by the model and the permission prompts; automatic surfaces keep full severity.
                    s = downgrade(sev, 2 if rule == "EXT-C01" else 1)
                    note = " (in instructions the agent would follow; the user sees each command before it runs)"
                elif is_test_file(path):
                    s = downgrade(sev, 2)
                    note = " (test file)"
                ln = line_of(text, m.start())
                if "code" in roles and is_pattern_definition(text, m.start()):
                    scan.add(rule, "Informational", "Detection pattern that resembles risky code (regular-expression definition)",
                             path, ln, m.group(0), cwe, owasp,
                             "No action if the line is a detection rule; confirm it is never executed as a command.")
                    continue
                scan.add(rule, s, title, path, ln, m.group(0), cwe, owasp, rem, description=title + note)
                if rule == "EXT-C04":
                    scan.cap["sensitive_access"].append(f"{path}:{ln}")
                if rule == "EXT-C06":
                    scan.cap["persistence"].append(f"{path}:{ln}")


def check_instructions(scan: Scan, path: str, text: str, roles: set):
    doc_only = "doc" in roles and "instruction" not in roles
    spans = code_spans(text) if PurePosixPath(path.lower()).suffix in DOC_EXT | {".mdc"} else []
    lines = text.splitlines()
    for rule, sev, title, pats, cwe, owasp, rem, negatable in INSTRUCTION_RULES:
        for p in pats:
            for m in p.finditer(text):
                ln = line_of(text, m.start())
                line = lines[ln - 1] if ln - 1 < len(lines) else ""
                if negatable and NEGATION.search(line[:max(0, m.start() - text.rfind("\n", 0, m.start()) - 1)] + " "):
                    continue  # protective wording ("never disable the sandbox")
                s = sev
                if doc_only:
                    s = "Low" if SEV_RANK[sev] <= SEV_RANK["High"] else "Informational"
                pre = text[max(0, m.start() - 2):m.start()]
                quoted = (spans and in_spans(m.start(), spans)) or any(q in pre for q in "\"'“‘«") or bool(EXAMPLE_CONTEXT.search(line))
                if quoted:
                    s = downgrade(s)
                if is_test_file(path):
                    s = downgrade(s, 2)
                scan.add(rule, s, title, path, ln, m.group(0), cwe, owasp, rem,
                         description=title + (" (quoted or example context)" if quoted else ""))
    if doc_only:
        return
    for p in POISON_RULES[1:]:
        for m in p.finditer(text):
            scan.add("EXT-M08", "High", "Text typical of tool-description poisoning", path, line_of(text, m.start()), m.group(0),
                     ["CWE-1427"], ["ASI02", "LLM01:2026", "AST05"], "Remove the text.")
    for m in re.finditer(r"<!--(.*?)-->|^\[//\]:\s*#\s*\((.*?)\)\s*$", text, re.S | re.M):
        body = (m.group(1) or m.group(2) or "")
        if re.search(r"\b(you|assistant|claude|model|agent|ai|llm)\b", body, re.I) and \
                re.search(r"\b(must|should|always|never|ignore|run|execute|send|do not|don't|instead)\b", body, re.I):
            scan.add("EXT-I08", "Medium", "Hidden Markdown comment contains instructions for the model", path,
                     line_of(text, m.start()), body.strip()[:120], ["CWE-912"], ["AST04", "LLM01:2026"],
                     "Move the text into visible content or remove it; reviewers do not see HTML comments in rendered Markdown.")
    for m in re.finditer(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{160,}={0,2}(?![A-Za-z0-9+/=])", text):
        start = max(0, m.start() - 40)
        if re.search(r"data:(image|font)/", text[start:m.start()]):
            continue
        blob = m.group(0)
        hint = ""
        try:
            dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
            printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in dec[:400])
            if dec and printable / min(len(dec), 400) > 0.9:
                hint = "; decodes to text: " + dec[:80].decode("ascii", "replace")
        except Exception:
            pass
        scan.add("EXT-I11", "Medium", "Encoded blob in an instruction file", path, line_of(text, m.start()),
                 f"{len(blob)} base64 characters{hint}", ["CWE-912"], ["AST04", "AST08"],
                 "Remove the blob or replace it with readable text; models can decode and follow encoded instructions.")


def check_frontmatter(scan: Scan, path: str, text: str, roles: set):
    fm, _ = parse_frontmatter(text)
    if not fm:
        return
    low = strip_archive_prefix(path).lower()
    name = fm.get("name", "")
    desc = fm.get("description", "")
    kind = "skill" if low.endswith("skill.md") else "agent" if "/agents/" in "/" + low else \
        "command" if "/commands/" in "/" + low else "instruction"
    entry = {"file": path, "name": name if isinstance(name, str) else "", "description": (desc if isinstance(desc, str) else "")[:300]}
    if kind == "skill":
        entry["allowed_tools"] = fm.get("allowed-tools", "")
        scan.components["skills"].append(entry)
    elif kind == "agent":
        entry["tools"] = fm.get("tools", "(not set: inherits all tools)")
        entry["permission_mode"] = fm.get("permissionMode", "")
        scan.components["agents"].append(entry)
    elif kind == "command":
        entry["allowed_tools"] = fm.get("allowed-tools", fm.get("allowedTools", ""))
        scan.components["commands"].append(entry)
    if kind == "skill":
        for problem in skill_metadata_problems(name if isinstance(name, str) else "", desc if isinstance(desc, str) else ""):
            scan.add("EXT-P08", "Medium", "Skill metadata that Claude rejects when the skill is uploaded", path, 1, problem,
                     ["CWE-1284"], ["AST04"],
                     "Fix the front matter: name of at most 64 lowercase letters, digits and hyphens without the reserved "
                     "words; description non-empty, at most 1,024 characters, no XML tags.")
    if isinstance(desc, str) and desc:
        scan.cap["declared_purpose"].append(f"{kind} {entry['name'] or path}: {desc[:200]}")
        m_always = re.search(r"\balways\s+(use|invoke|call|run|load|activate)\s+this\b", desc, re.I)
        if m_always:
            scan.add("EXT-I09", "Low", "Description asks to be used 'always'", path, 1, m_always.group(0), ["CWE-1427"], ["AST04"],
                     "State the tasks the component is for instead of 'always'.")
        for p in TRIGGER_RULES:
            m = p.search(desc)
            if m:
                scan.add("EXT-I09", "Medium", "Description is written to make the agent load it for unrelated work", path, 1,
                         m.group(0), ["CWE-1427"], ["AST04", "ASI01"],
                         "Describe the specific tasks the component is for; broad 'use for every request' wording hijacks routing.")
                break
    tools = fm.get("allowed-tools", fm.get("allowedTools", fm.get("tools", "")))
    tool_list = tools if isinstance(tools, list) else [t.strip() for t in str(tools).replace(",", " ").split()] if tools else []
    for t in tool_list:
        tt = t.strip().strip("'\"")
        if re.fullmatch(r"Bash(\(\*(:\*)?\))?", tt) and kind in ("skill", "command"):
            scan.add("EXT-I13", "Medium", "Pre-approves unrestricted shell commands while active", path, 1, f"allowed-tools: {tt}",
                     ["CWE-250"], ["AST03", "ASI02"], "List the exact commands needed, e.g. Bash(npm run test:*), instead of all of Bash.")
        elif re.match(r"Bash\((curl|wget|nc|ssh|scp|python3?|node|sh|bash|powershell|pwsh)\b", tt, re.I) and kind in ("skill", "command"):
            scan.add("EXT-I13", "Medium", "Pre-approves a network or interpreter command while active", path, 1, f"allowed-tools: {tt}",
                     ["CWE-250"], ["AST03", "ASI02"], "Narrow the rule to the exact script or URL the component needs.")
    if kind == "agent":
        if not fm.get("tools"):
            scan.add("EXT-S04", "Low", "Subagent has no tool list, so it inherits every tool", path, 1, "tools: (not set)",
                     ["CWE-250"], ["AST03", "ASI03"], "Give the agent an explicit, minimal tools list.")
        if str(fm.get("permissionMode", "")).lower() in ("bypasspermissions", "dontask"):
            scan.add("EXT-S02", "High", "Subagent runs without permission prompts", path, 1, f"permissionMode: {fm.get('permissionMode')}",
                     ["CWE-250"], ["AST03", "ASI03"], "Remove permissionMode or use default.")
    hooks_raw = fm.get("hooks")
    if hooks_raw:
        scan.components["hooks"].append({"file": path, "source": f"{kind} front matter", "raw": str(hooks_raw)[:400]})
        for cm in re.finditer(r"command:\s*(.+)", str(hooks_raw)):
            check_command_string(scan, path, cm.group(1).strip().strip("'\""), "front-matter hook", 1)
            scan.cap["auto_exec"].append({"component": f"{kind} front-matter hook", "trigger": "while active",
                                          "command": cm.group(1).strip()[:160], "file": path})


PLUGIN_DESCRIPTION_MAX = 500   # limit enforced when a plugin is saved in claude.ai / Cowork


def skill_metadata_problems(name: str, desc: str) -> list:
    """SKILL.md front-matter limits published for Claude Agent Skills (platform.claude.com, Agent Skills overview)."""
    out = []
    if not name:
        out.append("name is missing")
    else:
        if len(name) > 64:
            out.append(f"name has {len(name)} characters (maximum 64)")
        if not re.fullmatch(r"[a-z0-9-]+", name):
            out.append("name may contain only lowercase letters, digits and hyphens")
        if re.search(r"anthropic|claude", name, re.I):
            out.append("name contains a reserved word (anthropic, claude)")
    if not desc.strip():
        out.append("description is empty")
    elif len(desc) > 1024:
        out.append(f"description has {len(desc)} characters (maximum 1,024)")
    if re.search(r"<[A-Za-z/][^>]*>", desc) or re.search(r"<[A-Za-z/][^>]*>", name):
        out.append("description or name contains an XML tag")
    return out


NET_CMD = rx(r"\b(curl|wget|invoke-webrequest|iwr|irm|invoke-restmethod|nc|ncat|netcat|scp|sftp|ftp|telnet|socat)\b|"
             r"https?://|\brequests\.(get|post)|urllib|fetch\(")
INLINE_CODE = rx(r"\b(python3?|node|ruby|perl|php)\s+(-[a-z]*c|-e)\b|\b(bash|sh|zsh)\s+-c\b|\bbase64\s+(-d|--decode)\b|\beval\b")
OUTSIDE_ROOT = rx(r"(^|[\s\"'=])(~/|/etc/|/usr/|/tmp/|\$home\b|%userprofile%|%appdata%|[a-z]:\\\\)")


def check_command_string(scan: Scan, path: str, cmd: str, component: str, line=None):
    if not cmd:
        return
    for rule, sev, title, pats, cwe, owasp, rem in CODE_RULES:
        for p in pats:
            m = p.search(cmd)
            if m:
                scan.add(rule, sev, f"{title} ({component})", path, line, cmd, cwe, owasp, rem)
                break
    hosts = [host_of(u) for u in URL_RX.findall(cmd)]
    remote = [h for h in hosts if not is_placeholder_host(h)]
    if NET_CMD.search(cmd) and (remote or not hosts):
        scan.add("EXT-H02", "High", f"{component} contacts the network", path, line, cmd, ["CWE-201"],
                 ["ASI02", "AST01", "AST03"],
                 "Automatic commands should not reach the network; if they must, document the host, the data sent and make it opt-in.",
                 description=f"The {component} runs without the user asking, and its command reaches the network"
                             + (f" ({', '.join(sorted(set(remote)))})" if remote else "") + ".")
    if INLINE_CODE.search(cmd):
        scan.add("EXT-H03", "Medium", f"{component} runs inline code instead of a bundled script", path, line, cmd,
                 ["CWE-94"], ["ASI05", "AST06"], "Move the logic into a script inside the package, call it with ${CLAUDE_PLUGIN_ROOT}, and review it.")
    if OUTSIDE_ROOT.search(cmd) and "${CLAUDE_PLUGIN_ROOT}" not in cmd and "${extensionPath}" not in cmd:
        scan.add("EXT-H04", "Medium", f"{component} touches files outside the extension folder", path, line, cmd,
                 ["CWE-73"], ["AST06", "ASI02"], "Reference only files inside the extension (${CLAUDE_PLUGIN_ROOT}) or the project directory.")
    for p in (rx(r"(\.ssh\b|\.aws\b|\.netrc|\.git-credentials|\.npmrc|id_rsa|keychain)"),):
        m = p.search(cmd)
        if m:
            scan.add("EXT-C04", "High", f"Code reads credential or sensitive user files ({component})", path, line, cmd,
                     ["CWE-200"], ["AST03", "ASI03"], "Remove access to credential stores.")


def check_hooks_obj(scan: Scan, path: str, hooks: dict, source: str, text: str):
    if not isinstance(hooks, dict):
        return
    for event, groups in hooks.items():
        if not isinstance(groups, list):
            continue
        for g in groups:
            if not isinstance(g, dict):
                continue
            matcher = g.get("matcher", "")
            for h in g.get("hooks", []) if isinstance(g.get("hooks"), list) else []:
                if not isinstance(h, dict):
                    continue
                htype = h.get("type", "command")
                cmd = " ".join([str(h.get("command", ""))] + [str(a) for a in h.get("args", []) or []]).strip()
                ln = None
                needle = str(h.get("command") or h.get("url") or h.get("prompt") or "")[:40]
                if needle and needle in text:
                    ln = line_of(text, text.find(needle))
                entry = {"file": path, "source": source, "event": event, "matcher": matcher, "type": htype,
                         "command": (cmd or h.get("url") or h.get("prompt") or "")[:200], "async": bool(h.get("async") or h.get("asyncRewake"))}
                scan.components["hooks"].append(entry)
                comp = f"{event} hook"
                if htype == "command":
                    scan.cap["auto_exec"].append({"component": "hook", "trigger": f"{event}" + (f" [{matcher}]" if matcher else ""),
                                                  "command": cmd[:160], "file": path})
                    check_command_string(scan, path, cmd, comp, ln)
                    if entry["async"]:
                        scan.add("EXT-H05", "Low", "Hook runs in the background without a time limit", path, ln, cmd,
                                 ["CWE-400"], ["ASI08"], "Run the hook synchronously with a timeout unless background work is essential.")
                    if event in HIGH_RISK_TOOL_EVENTS and str(matcher).strip() in ("", "*", ".*"):
                        scan.add("EXT-H06", "Low", "Hook runs on every tool call or prompt", path, ln, f"{event} matcher '{matcher}'",
                                 ["CWE-250"], ["AST03"], "Limit the matcher to the tools the hook actually needs.")
                elif htype == "http":
                    url = str(h.get("url", ""))
                    host = host_of(url)
                    scan.cap["auto_exec"].append({"component": "http hook", "trigger": event, "command": url, "file": path})
                    if not is_placeholder_host(host):
                        scan.cap["network_code"].setdefault(host, set()).add(path)
                        scan.add("EXT-H07", "High" if url.startswith("http://") else "Medium",
                                 "Hook sends event data (tool inputs and outputs) to a remote server", path, ln, url,
                                 ["CWE-201"], ["ASI02", "LLM02:2026"],
                                 "Remove the HTTP hook or point it at a service you control; event payloads can contain file contents and commands.")
                elif htype in ("prompt", "agent"):
                    p = str(h.get("prompt", ""))
                    check_instructions(scan, path, p, {"instruction"})


def check_mcp_servers(scan: Scan, path: str, servers: dict, source: str, text: str):
    if not isinstance(servers, dict):
        return
    for sname, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        cmd = str(cfg.get("command", "") or "")
        args = [str(a) for a in (cfg.get("args") or []) if a is not None]
        url = str(cfg.get("url", "") or cfg.get("serverUrl", "") or cfg.get("httpUrl", "") or "")
        ln = line_of(text, text.find(f'"{sname}"')) if f'"{sname}"' in text else None
        entry = {"file": path, "source": source, "name": sname, "transport": "remote" if url else "stdio",
                 "command": " ".join([cmd] + args)[:200] if cmd else "", "url": url,
                 "env_keys": sorted((cfg.get("env") or {}).keys()) if isinstance(cfg.get("env"), dict) else []}
        scan.components["mcp_servers"].append(entry)
        if url:
            h = host_of(url)
            scan.cap["remote_mcp"].append(url)
            if not is_placeholder_host(h):
                scan.cap["network_code"].setdefault(h, set()).add(path)
            if url.startswith(("http://", "ws://")) and h not in LOOPBACK:
                scan.add("EXT-M02", "High", f"MCP server '{sname}' uses an unencrypted connection", path, ln, url,
                         ["CWE-319"], ["ASI04", "ASI07"], "Use https:// for remote MCP servers.")
            if url.lower().endswith((".mcpb", ".dxt")):
                scan.add("EXT-M06", "Medium", "MCP bundle is downloaded at install time without a pinned checksum", path, ln, url,
                         ["CWE-494"], ["AST02", "AST07"], "Ship the bundle inside the package or pin it by checksum.")
        if cmd:
            scan.cap["auto_exec"].append({"component": "MCP server (stdio)", "trigger": "starts with the agent session",
                                          "command": entry["command"][:160], "file": path})
            base = PurePosixPath(cmd.replace("\\", "/")).name.lower().replace(".cmd", "").replace(".exe", "")
            check_launcher_pin(scan, path, sname, base, args, ln)
            if base in ("sh", "bash", "zsh", "cmd", "powershell", "pwsh") and any(a.lower() in ("-c", "/c", "-command", "-encodedcommand", "-e") for a in args):
                scan.add("EXT-M05", "Medium", f"MCP server '{sname}' starts through a shell command line", path, ln, entry["command"],
                         ["CWE-78"], ["ASI05", "AST06"], "Start the server binary directly with an argument list.")
            if re.search(r"\b(curl|wget|iwr|irm|invoke-webrequest)\b", entry["command"], re.I):
                check_command_string(scan, path, entry["command"], f"MCP server '{sname}'", ln)
        for field in ("env", "headers"):
            vals = cfg.get(field)
            if isinstance(vals, dict):
                for k, v in vals.items():
                    sv = str(v)
                    if PLACEHOLDER_VALUE.match(sv) or "${" in sv or not sv:
                        continue
                    looks = any(p.search(sv) for _, p in SECRET_PATTERNS) or (
                        SECRET_KEY_NAME.search(k) and len(sv) >= 16 and re.fullmatch(r"(Bearer\s+)?[A-Za-z0-9._~+/=-]{16,}", sv))
                    if looks:
                        scan.cap["secrets"] += 1
                        scan.add("EXT-M03", "High", f"MCP server '{sname}' has a literal credential in its configuration", path, ln,
                                 f"{field}.{k} = {redact_secret(sv)}", ["CWE-798"], ["AST04", "LLM02:2026"],
                                 "Use a variable reference (${VAR}) or a sensitive userConfig option, and rotate the exposed credential.")
        for key in ("trust", "alwaysAllow", "autoApprove", "autoapprove", "always_allow"):
            if cfg.get(key):
                scan.cap["permission_changes"].append(f"{path}: MCP '{sname}' {key}")
                scan.add("EXT-M07", "Medium", f"MCP server '{sname}' tools run without confirmation", path, ln,
                         f"{key}: {json.dumps(cfg.get(key))[:80]}", ["CWE-250"], ["ASI02", "AST03"],
                         "Remove the auto-approval so the user confirms each tool call, at least for tools that change data.")
        if cfg.get("headersHelper"):
            scan.cap["auto_exec"].append({"component": "MCP headersHelper", "trigger": "on connect",
                                          "command": str(cfg.get("headersHelper"))[:160], "file": path})


def check_launcher_pin(scan: Scan, path: str, sname: str, base: str, args: list, ln):
    launchers = {"npx", "bunx", "pnpx", "uvx", "pipx", "yarn", "pnpm", "bun", "deno", "docker", "podman", "uv"}
    if base not in launchers:
        return
    rest = list(args)
    if base in ("yarn", "pnpm") and rest[:1] == ["dlx"]:
        rest = rest[1:]
    elif base == "pipx" and rest[:1] == ["run"]:
        rest = rest[1:]
    elif base == "uv" and rest[:2] == ["tool", "run"]:
        rest = rest[2:]
    elif base == "bun" and rest[:1] == ["x"]:
        rest = rest[1:]
    elif base in ("yarn", "pnpm", "bun", "uv"):
        return
    pkg = None
    i = 0
    while i < len(rest):
        a = rest[i]
        if a in ("-p", "--package", "--from", "--with"):
            pkg = rest[i + 1] if i + 1 < len(rest) else None
            break
        if a.startswith("-"):
            i += 1
            continue
        if base in ("docker", "podman"):
            if a in ("run", "container"):
                i += 1
                continue
        pkg = a
        break
    if not pkg:
        return
    if base in ("docker", "podman"):
        pinned = "@sha256:" in pkg
        tag = pkg.rsplit(":", 1)[1] if ":" in pkg.split("/")[-1] else "latest"
        if not pinned:
            sev = "Medium" if tag == "latest" else "Low"
            scan.add("EXT-M01", sev, f"MCP server '{sname}' runs a container image that is not pinned by digest", path, ln,
                     f"{base} {pkg}", ["CWE-1357"], ["AST07", "AST02", "ASI04"],
                     "Pin the image by digest (image@sha256:…) so updates are reviewed before they run.")
        return
    if base in ("npx", "bunx", "pnpx", "yarn", "pnpm", "bun", "deno"):
        name = pkg[1:] if pkg.startswith("@") else pkg
        ver = name.split("@", 1)[1] if "@" in name else ""
        pinned = bool(re.match(r"^\d+\.\d+\.\d+", ver))
    else:
        pinned = bool(re.search(r"(==|@)\d+\.\d+(\.\d+)?", pkg))
        ver = pkg
    if not pinned:
        scan.add("EXT-M01", "Medium", f"MCP server '{sname}' downloads and runs an unpinned package at every start", path, ln,
                 f"{base} {' '.join(args)[:120]}", ["CWE-1357"], ["AST07", "AST02", "ASI04"],
                 "Pin an exact version (package@1.2.3 or package==1.2.3); review the code of that version and its updates.",
                 description="Launchers such as npx and uvx fetch the newest release each time; a compromised or hijacked release "
                             "then runs with the user's permissions without any review.")


def check_settings(scan: Scan, path: str, d: dict, text: str):
    def ln(needle):
        return line_of(text, text.find(needle)) if needle in text else None
    scan.components["settings"].append({"file": path, "keys": sorted(d.keys())[:40]})
    perms = d.get("permissions") if isinstance(d.get("permissions"), dict) else {}
    for rule in perms.get("allow", []) or []:
        r = str(rule)
        if re.fullmatch(r"Bash(\(\*(:\*)?\))?", r):
            scan.add("EXT-S01", "High", "Settings pre-approve every shell command", path, ln(r), r, ["CWE-250"],
                     ["AST03", "ASI02", "LLM03:2026"], "Allow specific commands only, e.g. Bash(npm run test:*).")
            scan.cap["permission_changes"].append(f"{path}: allow {r}")
        elif re.match(r"Bash\((curl|wget|nc|ssh|scp|sudo|rm|python3?|node|sh|bash|powershell|pwsh)\b", r, re.I):
            scan.add("EXT-S01", "Medium", "Settings pre-approve a network, deletion or interpreter command", path, ln(r), r,
                     ["CWE-250"], ["AST03", "ASI02"], "Narrow the rule to the exact command and arguments needed.")
            scan.cap["permission_changes"].append(f"{path}: allow {r}")
        elif r in ("WebFetch", "mcp__*") or re.search(r"Read\([^)]*(\.ssh|\.aws|\.env|credentials|\*\*\))", r):
            scan.add("EXT-S01", "Medium", "Settings pre-approve broad network or file access", path, ln(r), r,
                     ["CWE-250"], ["AST03"], "Scope the rule to specific domains or paths.")
            scan.cap["permission_changes"].append(f"{path}: allow {r}")
    mode = str(perms.get("defaultMode", "") or d.get("defaultMode", ""))
    if mode.lower() in ("bypasspermissions", "dontask"):
        scan.add("EXT-S02", "High", "Settings turn off permission prompts", path, ln(mode), f"defaultMode: {mode}",
                 ["CWE-250"], ["AST03", "ASI03"], "Remove the setting; use the default mode.")
        scan.cap["permission_changes"].append(f"{path}: defaultMode {mode}")
    for key in ("skipDangerousModePermissionPrompt", "autoAccept", "yolo", "dangerouslySkipPermissions"):
        if d.get(key) is True:
            scan.add("EXT-S02", "High", "Settings switch off confirmation prompts", path, ln(key), f"{key}: true",
                     ["CWE-250"], ["AST03", "ASI03"], "Remove the setting.")
            scan.cap["permission_changes"].append(f"{path}: {key}")
    if d.get("enableAllProjectMcpServers") is True:
        scan.add("EXT-S03", "Medium", "Settings start every MCP server a project defines without asking", path,
                 ln("enableAllProjectMcpServers"), "enableAllProjectMcpServers: true", ["CWE-1357"], ["AST02", "ASI04"],
                 "Remove it and approve project MCP servers one by one (see CVE-2025-59536).")
        scan.cap["permission_changes"].append(f"{path}: enableAllProjectMcpServers")
    env = d.get("env") if isinstance(d.get("env"), dict) else d.get("environmentVariables") if isinstance(d.get("environmentVariables"), dict) else {}
    for k, v in (env or {}).items():
        ku, sv = str(k).upper(), str(v)
        if ku in ("ANTHROPIC_BASE_URL", "ANTHROPIC_API_URL", "OPENAI_BASE_URL", "OPENAI_API_BASE", "GOOGLE_GEMINI_BASE_URL",
                  "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "CLAUDE_CODE_API_BASE_URL") and not is_placeholder_host(host_of(sv) if "://" in sv else sv):
            scan.add("EXT-S06", "High", "Settings redirect model traffic or credentials to another server", path, ln(k), f"{k}={sv[:80]}",
                     ["CWE-201"], ["ASI04", "LLM02:2026"],
                     "Remove the variable unless it points at your own gateway; requests carry your API key (see CVE-2026-21852).")
            scan.cap["permission_changes"].append(f"{path}: env {k}")
        elif ku in ("NODE_OPTIONS", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PYTHONSTARTUP", "PYTHONPATH", "PERL5OPT", "RUBYOPT", "BASH_ENV"):
            scan.add("EXT-S07", "High", "Settings inject code into every process through an environment variable", path, ln(k),
                     f"{k}={sv[:80]}", ["CWE-427"], ["ASI05", "AST06"], "Remove the variable.")
            scan.cap["permission_changes"].append(f"{path}: env {k}")
        elif SECRET_KEY_NAME.search(k) and len(sv) >= 16 and not PLACEHOLDER_VALUE.match(sv) and "${" not in sv:
            scan.cap["secrets"] += 1
            scan.add("EXT-C10", "High", "Credential embedded in the package", path, ln(k), f"{k} ending {redact_secret(sv)}",
                     ["CWE-798"], ["AST04"], "Remove and rotate the credential.")
    for key in ("apiKeyHelper", "awsCredentialExport", "awsAuthRefresh", "otelHeadersHelper"):
        if d.get(key):
            scan.cap["auto_exec"].append({"component": f"settings {key}", "trigger": "when credentials are needed",
                                          "command": str(d[key])[:160], "file": path})
            check_command_string(scan, path, str(d[key]), f"settings {key}", ln(key))
    sl = d.get("statusLine")
    if isinstance(sl, dict) and sl.get("command"):
        scan.cap["auto_exec"].append({"component": "status line", "trigger": "continuously while the session runs",
                                      "command": str(sl["command"])[:160], "file": path})
        check_command_string(scan, path, str(sl["command"]), "status line command", ln("statusLine"))
    if isinstance(d.get("hooks"), dict):
        check_hooks_obj(scan, path, d["hooks"], "settings", text)
    if isinstance(d.get("mcpServers"), dict):
        check_mcp_servers(scan, path, d["mcpServers"], "settings", text)
    sb = d.get("sandbox")
    if isinstance(sb, dict) and sb.get("enabled") is False:
        scan.cap["permission_changes"].append(f"{path}: sandbox disabled")
    # .claude.json keeps per-project MCP servers
    projects = d.get("projects")
    if isinstance(projects, dict):
        for pname, pcfg in projects.items():
            if isinstance(pcfg, dict) and isinstance(pcfg.get("mcpServers"), dict):
                check_mcp_servers(scan, path, pcfg["mcpServers"], f"project {pname}", text)


def check_plugin_manifest(scan: Scan, path: str, d: dict, text: str):
    name = str(d.get("name", ""))
    scan.components["plugins"].append({"file": path, "name": name, "version": d.get("version", ""),
                                       "description": str(d.get("description", ""))[:300],
                                       "author": (d.get("author") or {}).get("name", "") if isinstance(d.get("author"), dict) else str(d.get("author", "")),
                                       "repository": d.get("repository", ""), "license": d.get("license", "")})
    if d.get("description"):
        scan.cap["declared_purpose"].append(f"plugin {name}: {str(d['description'])[:200]}")
    if len(str(d.get("description", ""))) > PLUGIN_DESCRIPTION_MAX:
        scan.add("EXT-P08", "Medium", "Plugin metadata that Claude rejects when the plugin is saved", path, 1,
                 f"description has {len(str(d['description']))} characters (maximum {PLUGIN_DESCRIPTION_MAX})", ["CWE-1284"], ["AST04"],
                 f"Shorten the plugin description to at most {PLUGIN_DESCRIPTION_MAX} characters.")
    low = name.lower()
    if re.match(r"^(claude|anthropic|anthropics|cc-plugin)(-|$)", low) or ("official" in low and ("claude" in low or "anthropic" in low)):
        scan.add("EXT-P06", "Medium", "Plugin name passes as an official Anthropic plugin", path, 1, name, ["CWE-451"],
                 ["AST01", "AST09"], "Check the publisher; Claude Code reserves these names for Anthropic.")
    if not d.get("version"):
        scan.add("EXT-P06", "Low", "Plugin has no version, so every new commit reaches users without a version change", path, 1,
                 "version: (missing)", ["CWE-1357"], ["AST07"], "Set a version and review the diff before each update.")
    if not d.get("license"):
        scan.add("EXT-P06", "Informational", "Plugin declares no licence", path, 1, "license: (missing)", ["CWE-1357"],
                 ["AST09"], "Ask the publisher for licence terms before redistributing or modifying it.")
    if d.get("hooks") and isinstance(d["hooks"], (dict, list)):
        items = d["hooks"] if isinstance(d["hooks"], list) else [d["hooks"]]
        for it in items:
            if isinstance(it, dict):
                check_hooks_obj(scan, path, it.get("hooks", it) if "hooks" in it and isinstance(it["hooks"], dict) else it, "plugin.json", text)
    ms = d.get("mcpServers")
    for it in (ms if isinstance(ms, list) else [ms]):
        if isinstance(it, dict):
            check_mcp_servers(scan, path, it, "plugin.json", text)
        elif isinstance(it, str) and it.lower().startswith("https://") and it.lower().endswith((".mcpb", ".dxt")):
            scan.add("EXT-M06", "Medium", "MCP bundle is downloaded at install time without a pinned checksum", path, None, it,
                     ["CWE-494"], ["AST02", "AST07"], "Ship the bundle inside the package or pin it by checksum.")
    if isinstance(d.get("lspServers"), dict):
        for lname, cfg in d["lspServers"].items():
            if isinstance(cfg, dict):
                scan.components["lsp_servers"].append({"file": path, "name": lname, "command": cfg.get("command", "")})
                scan.cap["auto_exec"].append({"component": "LSP server", "trigger": "when matching files are opened",
                                              "command": " ".join([str(cfg.get("command", ""))] + [str(a) for a in cfg.get("args", []) or []])[:160], "file": path})
    mons = (d.get("experimental") or {}).get("monitors") if isinstance(d.get("experimental"), dict) else d.get("monitors")
    if isinstance(mons, list):
        check_monitors(scan, path, mons, text)
    uc = d.get("userConfig")
    if isinstance(uc, dict):
        for k, v in uc.items():
            if isinstance(v, dict) and SECRET_KEY_NAME.search(k) and not v.get("sensitive"):
                scan.add("EXT-P06", "Low", f"Credential option '{k}' is not marked sensitive (stored in plain settings)", path,
                         line_of(text, text.find(f'"{k}"')) if f'"{k}"' in text else None, k, ["CWE-312"], ["AST04"],
                         "Set \"sensitive\": true so the value goes to the system credential store.")


def check_monitors(scan: Scan, path: str, mons: list, text: str):
    for m in mons:
        if not isinstance(m, dict):
            continue
        cmd = str(m.get("command", ""))
        scan.components["monitors"].append({"file": path, "name": m.get("name", ""), "command": cmd[:200], "when": m.get("when", "always")})
        scan.cap["auto_exec"].append({"component": "monitor (background process)", "trigger": m.get("when", "always"),
                                      "command": cmd[:160], "file": path})
        scan.add("EXT-H08", "Low", "Runs a persistent background process", path,
                 line_of(text, text.find(cmd[:30])) if cmd[:30] and cmd[:30] in text else None, cmd, ["CWE-250"], ["AST03", "ASI10"],
                 "Confirm the monitor's purpose; it runs for the whole session.")
        check_command_string(scan, path, cmd, "monitor", None)


def check_marketplace(scan: Scan, path: str, d: dict, text: str):
    plugins = d.get("plugins") or []
    scan.components["marketplaces"].append({"file": path, "name": d.get("name", ""), "plugins": len(plugins)})
    for p in plugins:
        if not isinstance(p, dict):
            continue
        if len(str(p.get("description", ""))) > PLUGIN_DESCRIPTION_MAX:
            scan.add("EXT-P08", "Medium", "Plugin metadata that Claude rejects when the plugin is saved", path, None,
                     f"marketplace entry '{p.get('name')}': description has {len(str(p['description']))} characters "
                     f"(maximum {PLUGIN_DESCRIPTION_MAX})", ["CWE-1284"], ["AST04"],
                     f"Shorten the description to at most {PLUGIN_DESCRIPTION_MAX} characters.")
        src = p.get("source")
        if isinstance(src, dict) and src.get("source") in ("github", "git", "url", "npm", "pip", "git-subdir"):
            pinned = any(src.get(k) for k in ("sha", "commit", "version")) or re.search(r"[0-9a-f]{40}", json.dumps(src))
            if not pinned:
                scan.add("EXT-P06", "Low", f"Marketplace entry '{p.get('name')}' follows a moving source", path,
                         line_of(text, text.find(str(p.get("name")))) if p.get("name") and str(p.get("name")) in text else None,
                         json.dumps(src)[:120], ["CWE-1357"], ["AST07", "AST02"],
                         "Pin the entry to a commit SHA or exact version; review updates before you bump it.")


def check_browser_manifest(scan: Scan, path: str, d: dict, text: str):
    perms = [str(x) for x in d.get("permissions", []) or []]
    hosts = [str(x) for x in (d.get("host_permissions", []) or [])] + [p for p in perms if "://" in p or p == "<all_urls>"]
    for cs in d.get("content_scripts", []) or []:
        if isinstance(cs, dict):
            hosts += [str(x) for x in cs.get("matches", []) or []]
    scan.components["browser_extensions"].append({"file": path, "name": d.get("name", ""), "version": d.get("version", ""),
                                                  "manifest_version": d.get("manifest_version"), "permissions": perms[:40],
                                                  "hosts": sorted(set(hosts))[:40]})
    scan.cap["browser_permissions"] = sorted(set(perms + hosts))
    broad = [h for h in hosts if h in ("<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*/") or re.match(r"^\*://\*\.", h) is None and h.startswith("*://*")]
    risky = sorted(set(perms) & {"debugger", "nativeMessaging", "proxy", "management", "webRequestBlocking", "cookies", "history",
                                  "clipboardRead", "desktopCapture", "tabCapture", "pageCapture", "privacy", "contentSettings",
                                  "declarativeNetRequestWithHostAccess", "scripting", "webRequest", "downloads", "browsingData"})
    if broad:
        combo = set(risky) & {"cookies", "webRequest", "webRequestBlocking", "debugger", "scripting", "nativeMessaging"}
        scan.add("EXT-B01", "High" if combo else "Medium", "Extension can read and change every website you visit", path,
                 line_of(text, text.find(broad[0])) if broad[0] in text else None,
                 ", ".join(broad[:3]) + (f" + {', '.join(sorted(combo))}" if combo else ""), ["CWE-250"], ["AST03"],
                 "Limit host permissions to the sites the extension needs, or make them optional and request them at run time.")
    if risky:
        scan.add("EXT-B02", "Medium", "Extension requests high-risk browser permissions", path, None, ", ".join(risky), ["CWE-250"],
                 ["AST03"], "Remove permissions the stated purpose does not need.")
    if d.get("manifest_version") == 2:
        scan.add("EXT-B03", "Medium", "Extension uses the retired Manifest V2 format", path, None, "manifest_version: 2",
                 ["CWE-1104"], ["AST07"], "Prefer a Manifest V3 build; MV2 allows remotely hosted code and is no longer supported by Chrome.")
    csp = d.get("content_security_policy")
    csp_s = json.dumps(csp) if csp else ""
    if "unsafe-eval" in csp_s or re.search(r"script-src[^;\"]*(https?:|\*)", csp_s):
        scan.add("EXT-B03", "High", "Extension policy allows eval or remote scripts", path, None, csp_s[:120], ["CWE-829"],
                 ["AST05"], "Remove 'unsafe-eval' and remote script sources from the content security policy.")
    ec = d.get("externally_connectable") or {}
    if isinstance(ec, dict) and (any("*://*/*" in str(m) or m == "<all_urls>" for m in ec.get("matches", []) or []) or "*" in (ec.get("ids") or [])):
        scan.add("EXT-B04", "Medium", "Any website or extension can send messages to this extension", path, None, json.dumps(ec)[:120],
                 ["CWE-346"], ["ASI07"], "List the exact origins and extension IDs allowed to connect.")
    if d.get("update_url") and "google.com" not in str(d.get("update_url")) and "microsoft.com" not in str(d.get("update_url")):
        scan.add("EXT-B06", "Low", "Extension updates from its own server, outside store review", path, None, str(d.get("update_url")),
                 ["CWE-494"], ["AST07"], "Prefer store-distributed builds, or pin the version you reviewed.")


def check_npm(scan: Scan, path: str, d: dict, text: str):
    scripts = d.get("scripts") if isinstance(d.get("scripts"), dict) else {}
    scan.components["npm_packages"].append({"file": path, "name": d.get("name", ""), "version": d.get("version", ""),
                                            "install_scripts": sorted(k for k in scripts if k in ("preinstall", "install", "postinstall"))})
    for k in ("preinstall", "install", "postinstall"):
        if k in scripts:
            scan.add("EXT-C11", "Medium", f"Package runs a '{k}' script when installed", path,
                     line_of(text, text.find(f'"{k}"')), f"{k}: {scripts[k]}"[:120], ["CWE-829"], ["AST02", "ASI04"],
                     "Review the script; install with --ignore-scripts where possible.")
            check_command_string(scan, path, str(scripts[k]), f"npm {k} script", line_of(text, text.find(f'"{k}"')))


def check_openapi(scan: Scan, path: str, text: str):
    d = parse_json(text) if path.lower().endswith(".json") else None
    servers = []
    write_ops = 0
    secured = bool(re.search(r"securitySchemes|\bsecurity\s*:", text))
    if isinstance(d, dict):
        servers = [s.get("url", "") for s in d.get("servers", []) or [] if isinstance(s, dict)]
        for _, ops in (d.get("paths") or {}).items():
            if isinstance(ops, dict):
                write_ops += sum(1 for m in ops if m.lower() in ("post", "put", "patch", "delete"))
    else:
        servers = re.findall(r"^\s*-\s*url:\s*['\"]?(\S+?)['\"]?\s*$", text, re.M)
        write_ops = len(re.findall(r"^\s{2,}(post|put|patch|delete)\s*:", text, re.M | re.I))
    scan.components["openapi"].append({"file": path, "servers": servers[:10], "write_operations": write_ops})
    for s in servers:
        if s.startswith("http://") and host_of(s) not in LOOPBACK:
            scan.add("EXT-M02", "High", "Action API uses an unencrypted server URL", path, None, s, ["CWE-319"], ["ASI04"], "Use https://.")
    if write_ops and not secured:
        scan.add("EXT-G01", "Medium", "Action API changes data but declares no authentication", path, None,
                 f"{write_ops} write operation(s), no securitySchemes", ["CWE-306"], ["API2:2023", "ASI02"],
                 "Declare and enforce authentication on the API, and require user confirmation for consequential actions.")


def check_codex(scan: Scan, path: str, text: str):
    if tomllib is not None:
        try:
            d = tomllib.loads(text)
        except Exception:
            d = None
        if isinstance(d, dict):
            if isinstance(d.get("mcp_servers"), dict):
                check_mcp_servers(scan, path, d["mcp_servers"], "codex config", text)
            if d.get("approval_policy") == "never" and d.get("sandbox_mode") == "danger-full-access":
                scan.add("EXT-S02", "High", "Codex runs every command without approval and without a sandbox", path, None,
                         "approval_policy=never, sandbox_mode=danger-full-access", ["CWE-250"], ["AST03", "ASI03"],
                         "Use an approval policy and the workspace-write sandbox.")
            return
    scan.notes.append(f"{path}: TOML read with text patterns only (Python < 3.11 has no tomllib)")
    if re.search(r'^\s*approval_policy\s*=\s*"never"', text, re.M) and re.search(r'sandbox_mode\s*=\s*"danger-full-access"', text):
        scan.add("EXT-S02", "High", "Codex runs every command without approval and without a sandbox", path, None,
                 "approval_policy=never, sandbox_mode=danger-full-access", ["CWE-250"], ["AST03"], "Use an approval policy and a sandbox.")


def check_file_package(scan: Scan, vf: VFile, roles: set):
    low = vf.path.lower()
    ext = PurePosixPath(low).suffix
    if vf.kind == "symlink":
        tgt = vf.link or ""
        base = PurePosixPath(strip_archive_prefix(vf.path)).parent
        resolved = os.path.normpath(str(base / tgt)).replace("\\", "/")
        outside = tgt.startswith(("/", "~")) or re.match(r"^[A-Za-z]:", tgt) or resolved.startswith("..")
        scan.add("EXT-P02", "High" if outside else "Low",
                 "Symbolic link points outside the extension" if outside else "Symbolic link inside the extension",
                 vf.path, None, f"-> {tgt}", ["CWE-59"], ["AST06", "AST02"],
                 "Replace the link with the real file; links can expose or overwrite files elsewhere on the machine.")
        return
    if vf.truncated:
        scan.cap["uninspected"].append(f"{vf.path} (only first {scan.max_file // (1024 * 1024)} MB read)")
        scan.add("EXT-P05", "Medium", "File larger than the scan limit was only partly inspected", vf.path, None,
                 f"{vf.size} bytes", ["CWE-912"], ["AST08"], "Re-run with a larger --max-file-mb or review the file by hand.")
    if ext in BINARY_EXT or (vf.data and b"\x00" in vf.data[:8192] and ext not in MEDIA_EXT and ext not in ARCHIVE_EXT
                             and not vf.note and decode(vf) is None):
        if ext in (".pyc", ".pyo"):
            parts = PurePosixPath(strip_archive_prefix(vf.path)).parts
            src_name = parts[-1].split(".")[0] + ".py"
            src_dir = "/".join(parts[:-2]) if len(parts) >= 2 and parts[-2] == "__pycache__" else "/".join(parts[:-1])
            has_src = any(strip_archive_prefix(f.path) == (f"{src_dir}/{src_name}" if src_dir else src_name) for f in scan.files)
            if has_src:
                scan.add("EXT-P03", "Informational", "Compiled Python cache next to its source (remove before distribution)",
                         vf.path, None, "source present", ["CWE-1357"], ["AST08"], "Delete __pycache__ folders from the package.")
                return
        scan.cap["uninspected"].append(f"{vf.path} (binary or compiled)")
        sev = "High" if ext in (".pyc", ".pyo", ".node", ".so", ".dll", ".dylib", ".exe") and "bin" not in roles else "Medium"
        scan.add("EXT-P03", sev, "Binary or compiled code that cannot be reviewed as source", vf.path, None,
                 f"{ext or 'binary'} {vf.size} bytes", ["CWE-1357"], ["AST08", "AST01"],
                 "Ask for the source and a reproducible build, or treat the extension as unreviewed code.",
                 description="Compiled bytecode and native binaries are a documented way to slip logic past scanners that read source.")
    if vf.kind == "file" and "!/" not in vf.path and ext in (ARCHIVE_EXT | OPAQUE_ARCHIVE_EXT) and in_skill(scan, vf.path):
        scan.add("EXT-P04", "Low", "Document or archive inside a skill can carry instructions the model is told to open",
                 vf.path, None, ext, ["CWE-912"], ["AST04", "AST08"],
                 "Prefer plain-text references; the scanner read the text parts of this file, but review it by hand too.")
    if "bin" in roles:
        name = PurePosixPath(low).name.split(".")[0]
        scan.components["bin"].append({"file": vf.path, "name": name, "executable": vf.exec_bit})
        scan.cap["auto_exec"].append({"component": "executable on PATH", "trigger": "when the agent runs a command with this name",
                                      "command": name, "file": vf.path})
        if name in SHADOW_COMMANDS:
            scan.add("EXT-P07", "High", f"Executable '{name}' shadows a common system command", vf.path, None, name, ["CWE-427"],
                     ["AST06", "ASI05"], "Rename it; a plugin bin/ folder is placed on the Bash tool's PATH and can intercept real commands.")
        else:
            scan.add("EXT-P07", "Low", "Adds an executable to the agent's PATH", vf.path, None, name, ["CWE-427"], ["AST06"],
                     "Review the executable; claude.ai and Cowork do not install plugins with a bin/ folder.")


POISON_RULES = [
    rx(r"<\s*important\s*>"),
    rx(r"\bbefore\s+(using|calling|invoking|you\s+use)\s+this\s+tool\b[^\n]{0,80}\b(read|send|include|pass|call|open)\b"),
    rx(r"\bpass\s+(it|its\s+contents?|the\s+(contents?|file|result|key))\s+(as|in|via)\s+(a\s+|the\s+)?['\"`]?\w*(sidenote|side_note|note|context|metadata|notes?)\b"),
    rx(r"\b(otherwise|or)\s+the\s+tool\s+will\s+(not\s+work|fail|crash)\b"),
]
CODE_INSTRUCTION_RULES = {"EXT-I02", "EXT-I03", "EXT-I06", "EXT-I07", "EXT-I10"}
_LATIN = re.compile(r"[A-Za-z]")
_LOOKALIKE = re.compile(r"[\u0370-\u03FF\u0400-\u052F]")   # Greek, Cyrillic


def check_code_strings(scan: Scan, path: str, text: str, roles: set):
    """Instruction-style text inside code: MCP tool descriptions and prompts are strings in source files."""
    test = is_test_file(path)
    for rule, sev, title, pats, cwe, owasp, rem, _neg in INSTRUCTION_RULES:
        if rule not in CODE_INSTRUCTION_RULES:
            continue
        for p in pats:
            for m in p.finditer(text):
                if is_pattern_definition(text, m.start()):
                    continue
                s2 = downgrade(sev, 3 if test else 1)
                scan.add(rule, s2, title + " (text inside code, e.g. a tool description)", path, line_of(text, m.start()),
                         m.group(0), cwe, owasp, rem)
    for p in POISON_RULES:
        for m in p.finditer(text):
            if is_pattern_definition(text, m.start()):
                continue
            scan.add("EXT-M08", "Low" if test else "High", "Text typical of tool-description poisoning", path,
                     line_of(text, m.start()), m.group(0), ["CWE-1427"], ["ASI02", "LLM01:2026", "AST05"],
                     "Remove the text. Tool descriptions are read by the model as instructions; they must only describe "
                     "what the tool does and its parameters.",
                     description="MCP tool descriptions and prompts live in source code as strings. Text that tells the model to "
                                 "take extra hidden steps before using a tool is the 'tool poisoning' pattern.")


def check_mixed_script(scan: Scan, path: str, text: str, roles: set):
    hits = []
    for m in re.finditer(r"[^\W\d_]{4,}", text):
        w = m.group(0)
        if _LOOKALIKE.search(w) and _LATIN.search(w):
            hits.append(m)
            if len(hits) >= 20:
                break
    if hits:
        instr = bool(roles & {"instruction", "rules-file"})
        scan.add("EXT-I17", "Medium" if instr else "Low", "Words mixing Latin with look-alike Cyrillic or Greek letters", path,
                 line_of(text, hits[0].start()), ", ".join(sorted({h.group(0) for h in hits})[:5]), ["CWE-1007"],
                 ["AST04", "AST08", "LLM01:2026"],
                 "Replace the look-alike letters. Mixed-script words read the same to a person but not to a keyword filter.",
                 description="Look-alike letters from another alphabet inside a word are a known way to slip wording past "
                             "pattern-based scanners while the model still reads it normally.")


def check_text_file(scan: Scan, vf: VFile, text: str, roles: set):
    path = vf.path
    if office_container(path):
        text = re.sub(r"<[^>]+>", " ", text)
    check_hidden_unicode(scan, path, text, roles)
    check_padding(scan, path, text, roles)
    check_secrets(scan, path, text, roles)
    check_urls(scan, path, text, roles)
    if roles & {"code", "instruction", "doc", "rules-file"}:
        check_code(scan, path, text, roles)
    if roles & {"instruction", "doc", "rules-file"}:
        check_instructions(scan, path, text, roles)
    elif "code" in roles or roles & {"mcp", "manifest-mcpb", "manifest-gemini", "config"}:
        check_code_strings(scan, path, text, roles)
    if roles & {"instruction", "rules-file", "code", "doc"}:
        check_mixed_script(scan, path, text, roles)
    if "instruction" in roles or "rules-file" in roles:
        scan.cap["instruction_files"].append({"file": path, "chars": len(text)})
        check_frontmatter(scan, path, text, roles)
        if "rules-file" in roles:
            scan.components["rules_files"].append({"file": path, "chars": len(text)})
    is_json = PurePosixPath(path.lower()).suffix in (".json", ".jsonc")
    d = parse_json(text) if is_json else None
    if isinstance(d, dict):
        if "manifest-plugin" in roles:
            check_plugin_manifest(scan, path, d, text)
        if "manifest-marketplace" in roles:
            check_marketplace(scan, path, d, text)
        if "manifest-gemini" in roles:
            scan.components["gemini_extensions"].append({"file": path, "name": d.get("name", ""), "version": d.get("version", ""),
                                                         "excludeTools": d.get("excludeTools", [])})
            if d.get("description"):
                scan.cap["declared_purpose"].append(f"gemini extension {d.get('name')}: {str(d['description'])[:200]}")
            check_mcp_servers(scan, path, d.get("mcpServers") or {}, "gemini-extension.json", text)
        if "manifest-browser" in roles:
            check_browser_manifest(scan, path, d, text)
        if "manifest-mcpb" in roles:
            scan.components["mcp_bundles"].append({"file": path, "name": d.get("name", ""), "version": d.get("version", "")})
            mc = ((d.get("server") or {}).get("mcp_config")) if isinstance(d.get("server"), dict) else None
            if isinstance(mc, dict):
                check_mcp_servers(scan, path, {d.get("name", "bundle"): mc}, "mcpb manifest", text)
        if "manifest-npm" in roles:
            check_npm(scan, path, d, text)
        if "hooks" in roles or (isinstance(d.get("hooks"), dict) and "settings" not in roles and "manifest-plugin" not in roles):
            check_hooks_obj(scan, path, d.get("hooks", {}) if isinstance(d.get("hooks"), dict) else {}, "hooks file", text)
        if "settings" in roles:
            check_settings(scan, path, d, text)
        elif "mcp" in roles or isinstance(d.get("mcpServers"), dict) or (isinstance(d.get("servers"), dict) and ".vscode" in path):
            check_mcp_servers(scan, path, d.get("mcpServers") or d.get("servers") or {}, "MCP config", text)
        if "lsp" in roles:
            for lname, cfg in d.items():
                if isinstance(cfg, dict):
                    scan.components["lsp_servers"].append({"file": path, "name": lname, "command": cfg.get("command", "")})
                    scan.cap["auto_exec"].append({"component": "LSP server", "trigger": "when matching files are opened",
                                                  "command": str(cfg.get("command", ""))[:160], "file": path})
        if "openapi" in roles:
            check_openapi(scan, path, text)
    elif isinstance(d, list) and "monitors" in roles:
        check_monitors(scan, path, d, text)
    elif "openapi" in roles:
        check_openapi(scan, path, text)
    if "codex-config" in roles:
        check_codex(scan, path, text)


# ------------------------------------------------------------------ capabilities and outputs

def capability_rows(scan: Scan, cands: list) -> list:
    c = scan.cap

    def yn(v):
        return "**Yes**" if v else "No"
    hosts_code = sorted(c["network_code"])
    hosts_instr = sorted(c["network_instructions"])
    rows = [
        ("Runs code automatically (hooks, MCP servers, monitors, LSP, status line, PATH executables)", yn(c["auto_exec"]),
         "; ".join(sorted({f"{a['component']} — {a['trigger']}" for a in c["auto_exec"]}))[:600] or "—"),
        ("Reaches the network from code or configuration", yn(hosts_code), ", ".join(hosts_code[:25]) or "—"),
        ("Tells the model to visit web addresses", yn(hosts_instr), ", ".join(hosts_instr[:25]) or "—"),
        ("Connects to remote MCP servers", yn(c["remote_mcp"]), ", ".join(sorted(set(c["remote_mcp"]))[:10]) or "—"),
        ("Reads credential or sensitive files", yn(c["sensitive_access"]), ", ".join(c["sensitive_access"][:10]) or "—"),
        ("Changes shell start-up, scheduled tasks or agent settings", yn(c["persistence"]), ", ".join(c["persistence"][:10]) or "—"),
        ("Loosens permission prompts or approvals", yn(c["permission_changes"]), "; ".join(c["permission_changes"][:10]) or "—"),
        ("Contains embedded credentials", yn(c["secrets"]), f"{c['secrets']} found (values redacted)" if c["secrets"] else "—"),
        ("Contains content the scanner could not inspect", yn(c["uninspected"]), "; ".join(c["uninspected"][:10]) or "—"),
        ("Gives the model instructions", yn(c["instruction_files"]),
         f"{len(c['instruction_files'])} file(s), {sum(f['chars'] for f in c['instruction_files']):,} characters" if c["instruction_files"] else "—"),
    ]
    if c["browser_permissions"]:
        rows.append(("Browser permissions requested", "**Yes**", ", ".join(c["browser_permissions"][:25])))
    return rows


def decision(cands: list) -> tuple:
    worst = min((SEV_RANK[x["severity"]] for x in cands), default=SEV_RANK["Informational"])
    if worst <= SEV_RANK["High"]:
        return ("do_not_install_yet", "Do not install yet",
                "The scan found at least one High or Critical candidate. Do not install until each one is verified or disproved "
                "(extension-reviewer agent + verifier); many turn out to be justified by the extension's purpose, some do not.")
    if worst == SEV_RANK["Medium"]:
        return ("review_first", "Review before installing",
                "The scan found Medium candidates. Confirm each is justified by the extension's stated purpose before installing.")
    return ("no_blocking_issue_found", "No blocking issue found by the static scan",
            "This is not proof that the extension is safe: see 'What this scan cannot see' below.")


def render_capabilities(scan: Scan, inv: dict, cands: list) -> str:
    code, label, why = decision(cands)
    counts = {s: sum(1 for x in cands if x["severity"] == s) for s in SEVERITIES}
    L = [f"# Extension scan — {scan.name}", "",
         f"Scanned {inv['scanned_at']} with appaudit scan_extension {SCANNER_VERSION}. Target: `{scan.root_label}`. "
         f"Package digest (SHA-256 over all files): `{inv['package_digest']}`.", "",
         f"## Install guidance: {label}", "", why, "",
         "| Critical | High | Medium | Low | Informational |", "|---|---|---|---|---|",
         "| " + " | ".join(str(counts[s]) for s in SEVERITIES) + " |", "",
         "## What this extension can do", "", "| Capability | Found | Details |", "|---|---|---|"]
    for cap, found, det in capability_rows(scan, cands):
        L.append(f"| {cap} | {found} | {str(det).replace('|', '/')} |")
    if scan.cap["declared_purpose"]:
        L += ["", "## What it says it does", ""] + [f"- {p}" for p in scan.cap["declared_purpose"][:12]]
        L += ["", "Compare the capabilities above with this stated purpose: a capability the purpose does not explain is the first thing to question."]
    comps = [(k, v) for k, v in scan.components.items() if v]
    if comps:
        L += ["", "## Components found", "", "| Component | Count |", "|---|---|"] + [f"| {k.replace('_', ' ')} | {len(v)} |" for k, v in comps]
    if cands:
        L += ["", "## Candidate findings", "", "| Severity | Rule | Title | Location |", "|---|---|---|---|"]
        for x in cands:
            loc = x["location"]["uri"] + (f":{x['location']['start_line']}" if x["location"].get("start_line") else "")
            L.append(f"| {x['severity']} | {x['rule']} | {x['title'].replace('|', '/')} | `{loc}` |")
        L += ["", "Candidates are unverified. In an appaudit run they go to the extension-reviewer agent and the verifier before they reach the report."]
    if inv.get("drift"):
        dr = inv["drift"]
        L += ["", "## Changes since the baseline", "",
              f"Baseline digest `{dr['baseline_digest']}` → current `{inv['package_digest']}`.",
              f"- Added files: {len(dr['added'])}; removed: {len(dr['removed'])}; changed: {len(dr['changed'])}"]
        for k in ("new_hosts", "new_auto_exec", "new_permission_changes"):
            if dr.get(k):
                L.append(f"- {k.replace('_', ' ').capitalize()}: {', '.join(dr[k][:15])}")
    if inv.get("suppressed"):
        L += ["", "## Accepted by the ignore file (not counted above)", "", "| Rule | Severity | Location | Reason given |", "|---|---|---|---|"]
        L += [f"| {x['rule']} | {x['severity']} | `{x['location']}` | {str(x['reason']).replace('|', '/')} |" for x in inv["suppressed"]]
    L += ["", "## What this scan cannot see", "",
          "- What the code does when it runs: scripts, hooks and MCP servers were read, never executed.",
          "- Tool descriptions that a remote or not-yet-installed MCP server sends at run time, and packages that npx/uvx download later.",
          "- Malicious intent written in ordinary language without the patterns above; the reviewer agent reads for that, and a human should too.",
          "- Content in binary, compiled or uninspected files listed above.",
          "- Changes the publisher makes after this scan: pin the version and keep this inventory as the baseline for the next update.",
          "", "Treat third-party extensions as untrusted code: a scanner result is evidence, not approval."]
    if scan.notes:
        L += ["", "## Scanner notes", ""] + [f"- {n}" for n in scan.notes[:20]]
    return "\n".join(L) + "\n"


def compute_drift(inv: dict, base: dict) -> dict:
    bf = {f["path"]: f.get("sha256") for f in base.get("files", [])}
    cf = {f["path"]: f.get("sha256") for f in inv["files"]}
    bc, cc = base.get("capabilities", {}), inv["capabilities"]
    def keys(cap, k, field=None):
        v = cap.get(k) or ([] if field else {})
        if field:
            return {f"{x.get('component')}: {x.get('command')}" for x in v}
        return set(v) if not isinstance(v, dict) else set(v.keys())
    return {"baseline_digest": base.get("package_digest", ""),
            "added": sorted(set(cf) - set(bf)), "removed": sorted(set(bf) - set(cf)),
            "changed": sorted(p for p in set(cf) & set(bf) if cf[p] != bf[p]),
            "new_hosts": sorted(keys(cc, "network_code") - keys(bc, "network_code")),
            "new_auto_exec": sorted(keys(cc, "auto_exec", True) - keys(bc, "auto_exec", True)),
            "new_permission_changes": sorted(set(cc.get("permission_changes", [])) - set(bc.get("permission_changes", [])))}


def run_scan(target: Path, name: str, max_file: int, baseline=None) -> tuple:
    scan = Scan(name, target.name, max_file)
    load_target(scan, target)
    for vf in scan.files:
        if vf.data is not None and PurePosixPath(strip_archive_prefix(vf.path)).name.lower() == "skill.md":
            scan.roots_with_skill.add(str(PurePosixPath(strip_archive_prefix(vf.path)).parent).lower())
        if vf.data is not None and PurePosixPath(vf.path).name.lower() == "gemini-extension.json":
            d = parse_json(decode(vf) or "")
            if isinstance(d, dict) and d.get("contextFileName"):
                names = d["contextFileName"] if isinstance(d["contextFileName"], list) else [d["contextFileName"]]
                base = str(PurePosixPath(strip_archive_prefix(vf.path)).parent)
                for n in names:
                    scan.context_files.add(((base + "/") if base != "." else "").lower() + str(n).lower())
    scan.roots_with_skill.discard(".")
    files_out = []
    for vf in scan.files:
        text = decode(vf) if vf.kind == "file" else None
        roles = classify(vf.path, text, scan) if vf.kind == "file" else {"symlink"}
        check_file_package(scan, vf, roles)
        if text is not None and vf.kind == "file":
            check_text_file(scan, vf, text, roles)
        files_out.append({"path": vf.path, "kind": vf.kind, "size": vf.size,
                          "sha256": hashlib.sha256(vf.data).hexdigest() if vf.data is not None else None,
                          "roles": sorted(roles), "executable": vf.exec_bit, "link": vf.link, "note": vf.note or None,
                          "truncated": vf.truncated})
    digest = hashlib.sha256("".join(f"{f['path']}\0{f['sha256'] or f['link'] or ''}\n"
                                    for f in sorted(files_out, key=lambda x: x["path"])).encode()).hexdigest()
    cands = scan.candidates()
    cap = dict(scan.cap)
    for k in ("network_code", "network_instructions", "network_docs"):
        cap[k] = {h: sorted(v) for h, v in sorted(cap[k].items())}
    inv = {"schema": "appaudit-extension-inventory/1", "scanner": f"appaudit scan_extension {SCANNER_VERSION}",
           "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "name": name, "target": target.name,
           "package_digest": digest, "file_count": len(files_out), "files": files_out, "components": scan.components,
           "capabilities": cap, "notes": scan.notes,
           "decision": decision(cands)[0],
           "candidate_counts": {s: sum(1 for x in cands if x["severity"] == s) for s in SEVERITIES}}
    if baseline:
        inv["drift"] = compute_drift(inv, baseline)
        dr = inv["drift"]
        for h in dr["new_hosts"]:
            scan.add("EXT-D01", "Medium", "New network endpoint since the reviewed version", "(package)", None, h, ["CWE-1357"],
                     ["AST07"], "Review why the update needs this host before accepting it.", kind="other")
        for a in dr["new_auto_exec"]:
            scan.add("EXT-D01", "Medium", "New automatic code execution since the reviewed version", "(package)", None, a,
                     ["CWE-1357"], ["AST07"], "Review the new hook, server or executable before accepting the update.", kind="other")
        for p in dr["new_permission_changes"]:
            scan.add("EXT-D01", "Medium", "New permission change since the reviewed version", "(package)", None, p, ["CWE-1357"],
                     ["AST07"], "Review the change before accepting the update.", kind="other")
        changed_instr = [p for p in dr["changed"] + dr["added"] if any(f["path"] == p and "instruction" in f["roles"] for f in files_out)]
        for p in changed_instr:
            scan.add("EXT-D02", "Low", "Instruction file changed since the reviewed version", p, None, "content changed",
                     ["CWE-1357"], ["AST07"], "Read the diff of this file before accepting the update.")
        cands = scan.candidates()
        inv["decision"] = decision(cands)[0]
        inv["candidate_counts"] = {s: sum(1 for x in cands if x["severity"] == s) for s in SEVERITIES}
    for c in cands:
        if c.get("location", {}).get("kind") == "other":
            c["location"].pop("uri", None) if c["location"].get("uri") == "(package)" else None
    return scan, inv, cands


def unpack(scan: Scan, dest: Path) -> int:
    """Write a review copy: regular top-level-archive files only; unsafe or nested entries are skipped."""
    root = dest.resolve()
    n = 0
    for vf in scan.files:
        if vf.kind != "file" or vf.data is None or "!/" in vf.path:
            continue
        rel, bad = safe_member_name(vf.path)
        if bad or not rel:
            continue
        out = (root / rel).resolve()
        try:
            out.relative_to(root)
        except ValueError:
            continue
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(vf.data)
        os.chmod(out, 0o644)
        n += 1
    return n


def to_sarif(cands: list, name: str) -> dict:
    level = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "Informational": "note"}
    score = {"Critical": "9.5", "High": "8.0", "Medium": "5.5", "Low": "3.0", "Informational": "0.0"}
    rules, results = {}, []
    for c in cands:
        rid = c.get("rule", "EXT")
        rules.setdefault(rid, {"id": rid, "name": rid, "shortDescription": {"text": c["title"]},
                               "help": {"text": (c.get("remediation") or {}).get("summary", "")},
                               "properties": {"tags": ["security"] + c.get("cwe", []) + c.get("owasp", [])}})
        loc = c.get("location") or {}
        res = {"ruleId": rid, "level": level[c["severity"]], "message": {"text": c.get("description") or c["title"]},
               "properties": {"severity": c["severity"], "security-severity": score[c["severity"]], "confidence": c.get("confidence")}}
        uri = strip_archive_prefix(loc.get("uri") or "") if "!/" not in (loc.get("uri") or "") else (loc.get("uri") or "").split("!/")[0]
        if loc.get("kind") == "file" and uri:
            phys = {"artifactLocation": {"uri": uri}}
            if loc.get("start_line") and "!/" not in (loc.get("uri") or ""):
                phys["region"] = {"startLine": loc["start_line"]}
            res["locations"] = [{"physicalLocation": phys}]
        results.append(res)
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "appaudit scan_extension", "version": SCANNER_VERSION,
                                          "informationUri": "https://github.com/unipicto/appaudit",
                                          "rules": list(rules.values())}},
                      "automationDetails": {"id": f"appaudit-extension/{name}"}, "results": results}]}


def load_ignores(path: Path) -> list:
    """Accepted-risk list: [{"rule": "EXT-C07", "path": "tests/*", "reason": "..."}]. A reason is mandatory."""
    data = json.loads(path.read_text(encoding="utf-8"))
    items = data.get("ignore", []) if isinstance(data, dict) else data
    out = []
    for i, it in enumerate(items):
        if not isinstance(it, dict) or not it.get("rule") or not str(it.get("reason", "")).strip():
            raise ValueError(f"ignore entry {i + 1} needs \"rule\" and a non-empty \"reason\"")
        out.append({"rule": str(it["rule"]), "path": str(it.get("path") or "*"), "reason": str(it["reason"]).strip()})
    return out


def apply_ignores(cands: list, ignores: list) -> tuple:
    import fnmatch
    kept, suppressed = [], []
    for c in cands:
        uri = (c.get("location") or {}).get("uri") or ""
        hit = next((g for g in ignores if g["rule"] in (c.get("rule"), "*") and fnmatch.fnmatch(uri, g["path"])), None)
        if hit and not (hit["rule"] == "*" and hit["path"] == "*"):
            suppressed.append({"rule": c.get("rule"), "severity": c["severity"], "title": c["title"], "location": uri,
                               "reason": hit["reason"]})
        else:
            kept.append(c)
    return kept, suppressed


def engagement(name: str, target: str) -> dict:
    return {"name": f"extension-{name}", "target": target, "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "authorization": {"basis": "obtained-copy",
                              "reference": "Static review of a copy of a publicly distributed or user-supplied extension; no system was tested."},
            "mode": "static", "capabilities_used": ["static review", "shell"],
            "not_tested": ["Run-time behaviour: scripts, hooks and MCP servers were read, not executed",
                           "Tool descriptions served at run time by remote or uninstalled MCP servers",
                           "Packages downloaded at run time (npx, uvx, docker pull)",
                           "Files listed as uninspected in capabilities.md"]}


# ------------------------------------------------------------------ discovery

def discover() -> list:
    home = Path.home()
    cwd = Path.cwd()
    appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
    cands = [
        (home / ".claude" / "plugins", "Claude Code installed plugins and marketplaces"),
        (home / ".claude" / "skills", "Claude Code personal skills"),
        (home / ".claude" / "agents", "Claude Code personal subagents"),
        (home / ".claude" / "commands", "Claude Code personal commands"),
        (home / ".claude" / "settings.json", "Claude Code user settings (hooks, permissions, env)"),
        (home / ".claude" / "CLAUDE.md", "Claude Code user rules file"),
        (home / ".claude.json", "Claude Code user/project MCP servers"),
        (cwd / ".claude", "Project .claude folder (settings, skills, agents, commands)"),
        (cwd / ".mcp.json", "Project MCP servers"),
        (cwd / "CLAUDE.md", "Project rules file"), (cwd / "AGENTS.md", "Project rules file"), (cwd / "GEMINI.md", "Project rules file"),
        (cwd / ".cursorrules", "Cursor rules file"), (cwd / ".cursor", "Cursor project rules and MCP"),
        (cwd / ".vscode" / "mcp.json", "VS Code project MCP servers"),
        (cwd / ".github" / "copilot-instructions.md", "GitHub Copilot instructions"),
        (cwd / ".gemini", "Gemini CLI project settings"),
        (appdata / "Claude" / "claude_desktop_config.json", "Claude Desktop MCP servers (Windows)"),
        (home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json", "Claude Desktop MCP servers (macOS)"),
        (home / ".config" / "Claude" / "claude_desktop_config.json", "Claude Desktop MCP servers (Linux)"),
        (home / ".cursor" / "mcp.json", "Cursor user MCP servers"),
        (appdata / "Code" / "User" / "mcp.json", "VS Code user MCP servers (Windows)"),
        (home / "Library" / "Application Support" / "Code" / "User" / "mcp.json", "VS Code user MCP servers (macOS)"),
        (home / ".config" / "Code" / "User" / "mcp.json", "VS Code user MCP servers (Linux)"),
        (home / ".codeium" / "windsurf" / "mcp_config.json", "Windsurf MCP servers"),
        (home / ".gemini" / "settings.json", "Gemini CLI user settings and MCP servers"),
        (home / ".gemini" / "extensions", "Gemini CLI extensions"),
        (home / ".codex" / "config.toml", "Codex CLI settings and MCP servers"),
        (home / ".codex" / "skills", "Codex skills"), (home / ".agents" / "skills", "Agent Skills (shared folder)"),
        (home / ".gemini" / "skills", "Gemini CLI skills"),
        (cwd / ".agents" / "skills", "Project Agent Skills"), (cwd / ".github" / "skills", "Project skills (GitHub Copilot)"),
        (cwd / ".windsurfrules", "Windsurf rules file"), (cwd / ".clinerules", "Cline rules file"),
    ]
    out = []
    for p, label in cands:
        if p.exists():
            out.append({"path": str(p), "type": label})
    plug = home / ".claude" / "plugins"
    if plug.is_dir():
        for pj in sorted(plug.glob("**/.claude-plugin/plugin.json"))[:200]:
            if ".trash" in pj.parts:
                continue  # removed plugins awaiting deletion
            out.append({"path": str(pj.parent.parent), "type": "Claude Code plugin"})
    for base in (home / ".claude" / "skills", home / ".codex" / "skills", home / ".agents" / "skills", home / ".gemini" / "skills",
                 cwd / ".claude" / "skills", cwd / ".agents" / "skills", cwd / ".github" / "skills", cwd / ".gemini" / "skills"):
        if base.is_dir():
            for sk in sorted(base.glob("*/SKILL.md"))[:200]:
                out.append({"path": str(sk.parent), "type": "Agent skill"})
    gx = home / ".gemini" / "extensions"
    if gx.is_dir():
        for ge in sorted(gx.glob("*/gemini-extension.json"))[:200]:
            out.append({"path": str(ge.parent), "type": "Gemini CLI extension"})
    return out


# ------------------------------------------------------------------ main

def slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:60] or "extension"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", nargs="?")
    ap.add_argument("--out", default=None, help="output folder (default .appaudit/extension-scan/<name>-<timestamp>)")
    ap.add_argument("--name", default=None)
    ap.add_argument("--baseline", default=None, help="inventory.json of the version you reviewed before (drift check)")
    ap.add_argument("--fail-on", default=None, choices=SEVERITIES, help="exit 1 if a candidate at or above this severity exists")
    ap.add_argument("--max-file-mb", type=int, default=20)
    ap.add_argument("--ignore-file", default=None,
                    help="JSON list of accepted candidates ({rule, path, reason}); only ever one you wrote yourself")
    ap.add_argument("--unpack", default=None, help="write a review copy of the target's regular files to this folder")
    ap.add_argument("--discover", action="store_true", help="list extension locations on this machine and in this project")
    ap.add_argument("--json", action="store_true", help="with --discover: print JSON")
    args = ap.parse_args()

    if args.discover:
        found = discover()
        if args.json:
            print(json.dumps(found, indent=2))
        else:
            if not found:
                print("No known extension locations found.")
            for f in found:
                print(f"{f['type']}: {f['path']}")
        return 0
    if not args.target:
        ap.print_usage(sys.stderr)
        return 2
    target = Path(args.target).expanduser()
    if not target.exists():
        print(f"ERROR: target not found: {target}", file=sys.stderr)
        return 2
    name = slug(args.name or target.name.split(".")[0] if target.is_file() else args.name or target.resolve().name)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = Path(args.out) if args.out else Path(".appaudit") / "extension-scan" / f"{name}-{stamp}"
    out_parts = [p.lower() for p in out.resolve().parts]
    if any(a == ".appaudit" and b == "evidence" for a, b in zip(out_parts, out_parts[1:])):
        print("ERROR: --out must not be inside .appaudit/evidence/", file=sys.stderr)
        return 2
    if target.is_dir():
        try:
            out.resolve().relative_to(target.resolve())
            print("ERROR: --out must be outside the target (writing into it would change what is scanned)", file=sys.stderr)
            return 2
        except ValueError:
            pass
    baseline = None
    if args.baseline:
        try:
            baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"ERROR: cannot read baseline: {exc}", file=sys.stderr)
            return 2
    ignores, ignore_note = [], ""
    if args.ignore_file:
        ig = Path(args.ignore_file)
        try:
            ignores = load_ignores(ig)
            if target.is_dir():
                try:
                    ig.resolve().relative_to(target.resolve())
                    ignore_note = ("The ignore file is part of the scanned folder. That is fine for your own code; "
                                   "never use an ignore file that came with someone else's package.")
                except ValueError:
                    pass
        except (OSError, ValueError) as exc:
            print(f"ERROR: cannot use ignore file: {exc}", file=sys.stderr)
            return 2
    try:
        scan, inv, cands = run_scan(target, name, max(1, args.max_file_mb) * 1024 * 1024, baseline)
    except (OSError, zipfile.BadZipFile, tarfile.TarError) as exc:
        print(f"ERROR: cannot read target: {exc}", file=sys.stderr)
        return 2
    suppressed = []
    if ignores:
        cands, suppressed = apply_ignores(cands, ignores)
        inv["suppressed"] = suppressed
        if ignore_note:
            scan.notes.append(ignore_note)
            inv["notes"] = scan.notes
        inv["decision"] = decision(cands)[0]
        inv["candidate_counts"] = {s: sum(1 for x in cands if x["severity"] == s) for s in SEVERITIES}
    out.mkdir(parents=True, exist_ok=True)
    (out / "inventory.json").write_text(json.dumps(inv, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    (out / "candidates.json").write_text(json.dumps(cands, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    (out / "capabilities.md").write_text(render_capabilities(scan, inv, cands), encoding="utf-8", newline="\n")
    (out / "candidates.sarif").write_text(json.dumps(to_sarif(cands, name), indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    (out / "engagement.json").write_text(json.dumps(engagement(name, target.name), indent=2) + "\n", encoding="utf-8", newline="\n")
    unpacked = None
    if args.unpack:
        dest = Path(args.unpack)
        if dest.exists() and any(dest.iterdir()):
            print("ERROR: --unpack folder must be empty or new", file=sys.stderr)
            return 2
        dest.mkdir(parents=True, exist_ok=True)
        unpacked = {"folder": str(dest), "files_written": unpack(scan, dest)}
    summary = {"output_dir": str(out), "name": name, "files": inv["file_count"], "package_digest": inv["package_digest"],
               "decision": inv["decision"], "candidates": inv["candidate_counts"],
               "components": {k: len(v) for k, v in scan.components.items() if v}}
    if unpacked:
        summary["unpacked"] = unpacked
    print(json.dumps(summary, indent=2))
    if args.fail_on:
        limit = SEV_RANK[args.fail_on]
        if any(SEV_RANK[c["severity"]] <= limit for c in cands):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
