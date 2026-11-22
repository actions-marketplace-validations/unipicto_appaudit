"""Shared helpers for the appaudit plugin hooks.

Standard library only; Python 3.9+. Imported by scope_guard.py, evidence_log.py,
session_start.py and scripts/verify_evidence.py.

Design rules:
- No network access and no DNS resolution from any hook.
- The scope file lives at <project>/.appaudit/scope.json; the evidence log at
  <project>/.appaudit/evidence/evidence.jsonl.
- Hosts are extracted from tool inputs by pattern. This is a guard rail, not a sandbox:
  a program that builds its own connection at runtime can bypass it (see README).
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shlex
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

SCOPE_REL = Path(".appaudit") / "scope.json"
EVIDENCE_REL = Path(".appaudit") / "evidence" / "evidence.jsonl"
GENESIS = "0" * 64
MAX_FIELD = 4000

# Hosts the agent may reach during an engagement without being targets: threat-intel feeds,
# standards bodies and package registries. Used only when scope.json has no "support_hosts".
DEFAULT_SUPPORT_HOSTS = [
    "www.cisa.gov", "cisa.gov",
    "api.first.org", "first.org", "www.first.org",
    "services.nvd.nist.gov", "nvd.nist.gov", "csrc.nist.gov", "nvlpubs.nist.gov",
    "api.osv.dev", "osv.dev",
    "api.github.com", "github.com",
    "euvd.enisa.europa.eu",
    "owasp.org", "*.owasp.org",
    "cwe.mitre.org",
    "eur-lex.europa.eu",
    "www.ncsc.nl", "ncsc.nl",
    "pypi.org", "files.pythonhosted.org", "registry.npmjs.org",
    "raw.githubusercontent.com",
]


class ScopeError(Exception):
    """The scope file exists but cannot be used. Callers fail closed."""


# ---------------------------------------------------------------- I/O helpers

def read_input() -> dict:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    data = json.loads(raw)
    return data if isinstance(data, dict) else {}


def project_dir(data: dict) -> Path:
    return Path(os.environ.get("CLAUDE_PROJECT_DIR") or data.get("cwd") or os.getcwd())


def emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False))
    sys.stdout.flush()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ---------------------------------------------------------------- scope file

def load_scope(pdir: Path) -> dict | None:
    path = pdir / SCOPE_REL
    if not path.exists():
        return None
    try:
        scope = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - any parse failure means fail closed
        raise ScopeError(f"{SCOPE_REL.as_posix()} is not valid JSON ({exc.__class__.__name__})")
    if not isinstance(scope, dict):
        raise ScopeError(f"{SCOPE_REL.as_posix()} must contain a JSON object")
    return scope


def is_open(scope: dict | None) -> bool:
    return bool(scope) and scope.get("status") == "open"


def parse_ts(value) -> datetime | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        raise ScopeError(f"window timestamp {value!r} is not ISO 8601")
    if dt.tzinfo is None:
        raise ScopeError(f"window timestamp {value!r} has no UTC offset")
    return dt


def window_ok(scope: dict, now: datetime) -> tuple[bool, str]:
    window = scope.get("window") or {}
    start = parse_ts(window.get("start"))
    end = parse_ts(window.get("end"))
    if start is None:
        return False, "no testing-window start is set in the scope file"
    if now < start:
        return False, f"the testing window starts {window.get('start')}"
    if end is not None and now > end:
        return False, f"the testing window ended {window.get('end')}"
    return True, ""


def _patterns(scope: dict, key: str) -> list:
    block = scope.get(key) or {}
    if isinstance(block, list):
        return block
    return list(block.get("hosts") or []) + list(block.get("cidrs") or [])


# ---------------------------------------------------------------- host matching

def norm_host(host: str) -> str:
    return host.strip().strip("[]").rstrip(".").lower()


def as_ip(text: str):
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def as_net(text: str):
    if "/" not in text:
        return None
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def host_matches(target: str, patterns) -> bool:
    """target is a hostname, an IP address or a CIDR range."""
    t_ip = as_ip(target)
    t_net = as_net(target)
    for raw in patterns or []:
        pat = norm_host(str(raw))
        if not pat:
            continue
        p_net = as_net(pat)
        if p_net is not None:
            if t_ip is not None and t_ip.version == p_net.version and t_ip in p_net:
                return True
            if t_net is not None and t_net.version == p_net.version and t_net.subnet_of(p_net):
                return True
            continue
        if t_ip is not None or t_net is not None:
            p_ip = as_ip(pat)
            if t_ip is not None and p_ip is not None and t_ip == p_ip:
                return True
            continue
        if pat.startswith("*."):
            if target.endswith("." + pat[2:]):
                return True
            continue
        if target == pat:
            return True
    return False


def classify(target: str, scope: dict, now: datetime) -> tuple[bool, str]:
    """Return (allowed, reason) for contacting target under an open engagement."""
    target = norm_host(target)
    if host_matches(target, _patterns(scope, "out_of_scope")):
        return False, f"{target} is explicitly out of scope"
    support = scope.get("support_hosts")
    if support is None:
        support = DEFAULT_SUPPORT_HOSTS
    if host_matches(target, support):
        return True, ""
    if not host_matches(target, _patterns(scope, "in_scope")):
        return False, f"{target} is not in the engagement scope"
    if scope.get("mode") != "active":
        return False, f"{target} is in scope, but the engagement is in static mode (no active testing authorized)"
    ok, why = window_ok(scope, now)
    if not ok:
        return False, f"{target} is in scope, but {why}"
    return True, ""


# ---------------------------------------------------------------- host extraction

URL_RE = re.compile(r"\b([a-zA-Z][a-zA-Z0-9+.\-]{1,15})://([^\s'\"<>`|;(){}\\]+)")
HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$")
IP_RANGE_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$")
FILE_EXT = {
    "txt", "json", "jsonl", "xml", "md", "py", "sh", "ps1", "csv", "log", "html", "htm", "yaml",
    "yml", "conf", "cfg", "ini", "toml", "out", "gz", "tgz", "zip", "tar", "pcap", "pcapng", "js",
    "ts", "tsx", "jsx", "css", "lock", "env", "pem", "crt", "key", "der", "bin", "img", "apk",
    "ipa", "jar", "war", "so", "dll", "exe", "pdf", "docx", "xlsx", "png", "jpg", "jpeg", "gif",
    "svg", "sql", "db", "sqlite", "bak", "old", "tmp", "nse", "rb", "go", "rs", "java", "c", "h",
    "cpp", "php", "pl", "lua", "dockerfile", "tf", "tfvars", "hcl", "sarif", "nmap", "gnmap",
    "cs", "cc", "hh", "hpp", "kt", "kts", "vb", "fs", "ml", "hs", "jl", "ex", "exs", "el", "nim", "swift", "dart",
    "scala", "clj", "erl", "vue", "svelte", "astro", "mjs", "cjs", "mts", "cts", "ipynb", "rst", "tex", "bat",
    "cmd", "psm1", "plist", "proto", "gradle", "properties", "whl", "egg", "deb", "rpm", "iso", "dmg", "msi",
    "plugin", "skill", "mcpb", "dxt", "xpi", "crx", "vsix", "map", "wasm", "pyc", "class", "o", "a", "s", "asm",
}
NET_TOOLS = {
    "curl", "wget", "http", "https", "httpie", "xh", "nmap", "masscan", "rustscan", "nc", "ncat",
    "netcat", "socat", "ssh", "scp", "sftp", "ftp", "telnet", "ping", "ping6", "traceroute",
    "tracert", "mtr", "dig", "nslookup", "host", "whois", "httpx", "nuclei", "sqlmap", "nikto",
    "ffuf", "gobuster", "dirb", "dirsearch", "feroxbuster", "wfuzz", "hydra", "medusa", "testssl",
    "testssl.sh", "sslscan", "sslyze", "openssl", "amass", "subfinder", "dnsx", "katana", "wpscan",
    "smbclient", "rpcclient", "enum4linux", "crackmapexec", "nxc", "msfconsole", "grpcurl",
    "websocat", "wscat", "mosquitto_sub", "mosquitto_pub", "redis-cli", "psql", "mysql", "mongo",
    "mongosh", "ldapsearch", "snmpwalk", "rsync", "zap.sh", "zap-cli", "burpsuite",
    "invoke-webrequest", "invoke-restmethod", "iwr", "irm", "test-netconnection",
}
NON_NET = {
    "grep", "egrep", "fgrep", "rg", "ag", "ack", "cat", "less", "more", "head", "tail", "sed",
    "awk", "find", "echo", "printf", "ls", "dir", "wc", "sort", "uniq", "cut", "tr", "jq", "yq",
    "diff", "file", "strings", "stat", "realpath", "basename", "dirname", "mkdir", "touch", "cd",
    "pwd", "true", "false", "test", "[", "select-string", "get-content", "type",
}
WRAPPERS = {"sudo", "doas", "env", "timeout", "nohup", "time", "nice", "stdbuf", "xargs", "command", "exec", "proxychains", "proxychains4", "torsocks"}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish", "pwsh", "powershell", "cmd"}
GIT_NET = {"clone", "fetch", "pull", "push", "ls-remote", "submodule", "remote"}
URL_KEYS = {
    "url", "urls", "uri", "href", "endpoint", "host", "hostname", "target", "targets", "domain",
    "base_url", "baseurl", "website", "site", "link", "address", "ip",
}


def host_from_url(url: str) -> str | None:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return norm_host(host) if host else None


def host_from_token(token: str, cwd: str | None = None) -> list[str]:
    t = token.strip().strip("'\"")
    if not t:
        return []
    if t.startswith("-"):
        if "=" in t:
            t = t.split("=", 1)[1]
        else:
            return []
    if "://" in t:
        host = host_from_url(t)
        return [host] if host else []
    if "@" in t:
        t = t.rsplit("@", 1)[1]
    net = as_net(t)
    if net is not None:
        return [str(net)]
    m = IP_RANGE_RE.match(t)
    if m:
        first, last = m.group(1) + m.group(2), m.group(1) + m.group(3)
        return [h for h in (first, last) if as_ip(h)]
    t = t.split("/", 1)[0]
    if t.count(":") == 1:
        t = t.split(":", 1)[0]
    t = norm_host(t)
    if not t:
        return []
    if t == "localhost" or as_ip(t) is not None:
        return [t]
    if HOST_RE.match(t) and t.rsplit(".", 1)[1] not in FILE_EXT:
        if cwd and os.path.exists(os.path.join(cwd, t)):
            return []
        return [t]
    return []


def _split_segments(command: str) -> list[str]:
    parts = re.split(r"\|\||&&|[;|\n&]|\$\(|`|\(|\)", command)
    return [p for p in parts if p.strip()]


def _tokens(segment: str) -> list[str]:
    try:
        return shlex.split(segment, posix=True)
    except ValueError:
        return segment.split()


def _program(tokens: list[str]) -> tuple[str, list[str]]:
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        base = os.path.basename(tok).lower()
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tok):  # leading VAR=value assignment
            i += 1
            continue
        if base in WRAPPERS:
            i += 1
            while i < len(tokens) and (tokens[i].startswith("-") or re.fullmatch(r"\d+[smhd]?", tokens[i])):
                i += 1
            continue
        break
    if i >= len(tokens):
        return "", []
    prog = os.path.basename(tokens[i]).lower()
    if prog.endswith(".exe"):
        prog = prog[:-4]
    return prog, tokens[i + 1:]


def hosts_from_command(command: str, cwd: str | None = None, depth: int = 0) -> set[str]:
    hosts: set[str] = set()
    if depth > 3 or not command:
        return hosts
    for segment in _split_segments(command):
        prog, args = _program(_tokens(segment))
        if not prog:
            continue
        if prog in SHELLS:
            for flag in ("-c", "-command", "/c"):
                if flag in [a.lower() for a in args]:
                    idx = [a.lower() for a in args].index(flag)
                    if idx + 1 < len(args):
                        hosts |= hosts_from_command(args[idx + 1], cwd, depth + 1)
            continue
        if prog in NON_NET:
            continue
        if prog == "git":
            sub = next((a for a in args if not a.startswith("-")), "")
            if sub not in GIT_NET:
                continue
        for m in URL_RE.finditer(segment):
            host = host_from_url(f"{m.group(1)}://{m.group(2)}")
            if host:
                hosts.add(host)
        if prog in NET_TOOLS:
            for i, arg in enumerate(args):
                hosts.update(host_from_token(arg, cwd))
                nxt = args[i + 1] if i + 1 < len(args) else ""
                if arg in ("--resolve", "--connect-to") and nxt:
                    # host:port:address (curl): the address is where the request really goes
                    m = re.match(r"^[^:]*:\d*:(\[[0-9a-fA-F:]+\]|[^:]+)(?::\d+)?$", nxt)
                    if m:
                        hosts.update(host_from_token(m.group(1), None))
                if arg in ("-H", "--header") and nxt.lower().startswith("host:"):
                    hosts.update(host_from_token(nxt.split(":", 1)[1].strip(), None))
    return hosts


# ---------------------------------------------------------------- soft signals (ask, not deny)

# Programs that are used almost only for scanning or attacking; without an open engagement the
# guard asks (or denies, per the scanner_gate option) before they run.
SCANNERS = {
    "nmap", "masscan", "rustscan", "nuclei", "sqlmap", "nikto", "ffuf", "gobuster", "dirb", "dirsearch",
    "feroxbuster", "wfuzz", "hydra", "medusa", "wpscan", "amass", "subfinder", "katana", "enum4linux",
    "crackmapexec", "nxc", "msfconsole", "zap.sh", "zap-cli", "burpsuite", "testssl", "testssl.sh", "sslscan",
    "sslyze", "httpx", "dnsx",
}
# Flags whose value is a file of targets or a saved request.
LIST_FLAGS = {"-iL", "-i", "--input-file", "-K", "--config", "-r", "-m", "-l", "-list", "--list", "-dL", "-request",
              "-request-file", "-L", "--targets", "-iR"}
COMMON_TLDS = {
    "com", "net", "org", "info", "biz", "edu", "gov", "mil", "int", "io", "app", "dev", "cloud", "online", "site",
    "xyz", "tech", "shop", "store", "blog", "page", "link", "live", "pro", "top", "club", "agency", "email",
    "systems", "network", "digital", "solutions", "services", "company", "group", "world", "today", "local",
    "internal", "lan", "corp", "home", "test", "example", "onion", "ai",
}
_OPAQUE = re.compile(
    r"\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|\|\s*(python3?|node|perl|ruby|php|pwsh|powershell)\b|(^|[;&|]\s*)eval\s|"
    r"\bbase64\s+(-d|--decode|-D)\b|\bxxd\s+-r\b|\$\(\s*(curl|wget)\b|<\(\s*(curl|wget)\b|"
    r"\b(iex|invoke-expression)\b|-e(nc|ncodedcommand)\s", re.IGNORECASE)


def _hostish(token: str, cwd: str | None) -> str | None:
    """A token that looks like a real internet host or address (stricter than host_from_token)."""
    t = token.strip().strip("'\"")
    if not t or t.startswith("-") and "=" not in t:
        return None
    if t.startswith("-"):
        t = t.split("=", 1)[1]
    if "://" in t:
        return host_from_url(t)
    if "@" in t:
        t = t.rsplit("@", 1)[1]
    t = t.split("/", 1)[0]
    if t.count(":") == 1:
        t = t.split(":", 1)[0]
    t = norm_host(t)
    ip = as_ip(t)
    if ip is not None:
        return t if t.count(".") == 3 or ":" in t else None
    if not HOST_RE.match(t):
        return None
    tld = t.rsplit(".", 1)[1]
    if tld in FILE_EXT or not (len(tld) == 2 or tld in COMMON_TLDS):
        return None
    if cwd and os.path.exists(os.path.join(cwd, token.strip("'\""))):
        return None
    return t


def _hosts_in_file(path: str, cwd: str | None) -> set[str] | None:
    """Hosts named in a target-list or saved-request file; None when the file cannot be read."""
    full = path if os.path.isabs(path) else os.path.join(cwd or os.getcwd(), path)
    try:
        if os.path.getsize(full) > 2 * 1024 * 1024:
            return None
        with open(full, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return None
    found: set[str] = set()
    for m in URL_RE.finditer(text):
        host = host_from_url(f"{m.group(1)}://{m.group(2)}")
        if host:
            found.add(host)
    for m in re.finditer(r"(?im)^\s*host:\s*(\S+)", text):
        found.update(host_from_token(m.group(1), None))
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and " " not in line:
            found.update(host_from_token(line, None))
    return found


def soft_signals(command: str, cwd: str | None = None) -> tuple[set[str], list[str]]:
    """Hosts and conditions the strict parser cannot be sure about. The guard asks the user about them.

    Returns (hosts, reasons): hosts found in arguments of programs the guard does not know, or in
    target-list files; reasons for commands whose real targets cannot be read from the command line.
    """
    hosts: set[str] = set()
    reasons: list[str] = []
    if not command:
        return hosts, reasons
    if _OPAQUE.search(command):
        reasons.append("the command builds or decodes what it runs at run time, so its targets cannot be checked")
    for segment in _split_segments(command):
        prog, args = _program(_tokens(segment))
        if not prog or prog in NON_NET:
            continue
        if prog == "git":
            sub = next((a for a in args if not a.startswith("-")), "")
            if sub not in GIT_NET:
                continue
        if prog in NET_TOOLS:
            for i, arg in enumerate(args):
                if arg in LIST_FLAGS and i + 1 < len(args) and not (arg == "-i" and prog not in ("wget",)) \
                        and not (arg in ("-r", "-m", "-l") and prog not in ("sqlmap", "nuclei", "httpx", "dnsx", "subfinder", "katana")) \
                        and not (arg == "-L" and prog not in ("hydra", "medusa")):
                    listed = _hosts_in_file(args[i + 1], cwd)
                    if listed is None:
                        reasons.append(f"targets are read from {args[i + 1]}, which the guard cannot read")
                    else:
                        hosts |= listed
            if prog in ("ssh", "scp", "sftp", "telnet", "ftp", "rsync"):
                for arg in args:
                    name = arg.rsplit("@", 1)[-1].split(":", 1)[0]
                    if name and not arg.startswith("-") and re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", name) \
                            and name != "localhost" and "/" not in arg and not (cwd and os.path.exists(os.path.join(cwd, arg))):
                        reasons.append(f"'{name}' is a host alias; the guard cannot tell which host it means")
                        break
            continue
        if prog in SHELLS:
            continue
        for arg in args:
            h = _hostish(arg, cwd)
            if h:
                hosts.add(h)
    return hosts, reasons


def scanner_in(command: str) -> str | None:
    """Name of the first scanning/attack tool the command starts, if any."""
    for segment in _split_segments(command or ""):
        prog, args = _program(_tokens(segment))
        if prog in SHELLS:
            low = [a.lower() for a in args]
            for flag in ("-c", "-command", "/c"):
                if flag in low and low.index(flag) + 1 < len(args):
                    inner = scanner_in(args[low.index(flag) + 1])
                    if inner:
                        return inner
        if prog in SCANNERS:
            return prog
    return None


def _walk(obj, key: str = ""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, str(k).lower())
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v, key)
    elif isinstance(obj, str):
        yield key, obj


def hosts_from_tool(tool_name: str, tool_input: dict, cwd: str | None = None) -> set[str]:
    tool_input = tool_input or {}
    hosts: set[str] = set()
    command = tool_input.get("command")
    if isinstance(command, str) and tool_name not in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        hosts |= hosts_from_command(command, cwd)
    for key, value in _walk(tool_input):
        if key == "command":
            continue
        value = value.strip()
        if key in URL_KEYS:
            for part in re.split(r"[\s,]+", value):
                hosts.update(host_from_token(part, None))
        elif re.fullmatch(r"[a-zA-Z][a-zA-Z0-9+.\-]{1,15}://\S+", value):
            host = host_from_url(value)
            if host:
                hosts.add(host)
    return {h for h in hosts if h}


# ---------------------------------------------------------------- protected files

WRITE_HINT = re.compile(
    r"(>|\btee\b|\bsed\s+-i|\bmv\b|\bcp\b|\brm\b|\btruncate\b|\bdd\b|\bchmod\b|\bln\b|"
    r"set-content|add-content|out-file|remove-item|move-item|copy-item|"
    r"\bperl\b|\bpython3?\b|\bnode\b|\bruby\b|\bjq\b.*>)",
    re.IGNORECASE,
)


PLUGIN_ROOT = Path(__file__).resolve().parent.parent
TRUSTED_SCRIPTS = (
    "scripts/verify_evidence.py",
    "skills/assess/scripts/build_outputs.py",
    "skills/assess/scripts/check_update.py",
    "skills/assess/scripts/merge_candidates.py",
    "skills/assess/scripts/compare_runs.py",
    "skills/assess/scripts/scan_extension.py",
)
_SHELL_META = re.compile(r"[;&|<>`\n]|\$\(")


def is_trusted_invocation(command: str) -> bool:
    """True only for one plain `python[3] [-I] <plugin script> args...` call.

    The script must resolve to one of TRUSTED_SCRIPTS under this plugin's own root; any shell
    operator, redirection or substitution disqualifies the command. These scripts only read
    the scope file and evidence log; they write reports elsewhere.
    """
    command = re.sub(r"\\\r?\n", " ", command)  # allow backslash line continuations
    if _SHELL_META.search(command):
        return False
    trusted = {os.path.normcase(str((PLUGIN_ROOT / rel).resolve())) for rel in TRUSTED_SCRIPTS}
    # POSIX parsing first; non-POSIX parsing keeps Windows backslash paths intact.
    for posix in (True, False):
        try:
            argv = [a.strip('"').strip("'") for a in shlex.split(command, posix=posix)]
        except ValueError:
            continue
        if not argv or Path(argv[0]).name.lower() not in ("python", "python3", "python.exe", "python3.exe", "py", "py.exe"):
            continue
        rest = argv[1:]
        while rest and rest[0] in ("-I", "-B", "-E", "-s", "-u", "-3"):
            rest = rest[1:]
        if not rest:
            continue
        try:
            script = os.path.normcase(str(Path(rest[0]).expanduser().resolve()))
        except (OSError, RuntimeError):
            continue
        if script in trusted:
            return True
    return False


def protected_target(tool_name: str, tool_input: dict) -> str | None:
    """Return a description if the call would change the scope file or evidence log."""
    tool_input = tool_input or {}
    for key in ("file_path", "notebook_path", "path"):
        value = tool_input.get(key)
        if isinstance(value, str) and tool_name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
            p = value.replace("\\", "/").lower()
            if p.endswith(".appaudit/scope.json"):
                return "the engagement scope file (.appaudit/scope.json)"
            if "/.appaudit/evidence/" in p or p.startswith(".appaudit/evidence/"):
                return "the evidence log (.appaudit/evidence/)"
    command = tool_input.get("command")
    if isinstance(command, str) and re.search(r"\.appaud|scope\.json|evidence\.jsonl", command.replace("\\", "/")):
        cleaned = re.sub(r"\d?>&\d|\d?>\s*/dev/null|\d?>\s*nul\b", " ", command, flags=re.IGNORECASE)
        if is_trusted_invocation(command):
            return None
        if WRITE_HINT.search(cleaned):
            if "evidence" in cleaned:
                return "the evidence log (.appaudit/evidence/)"
            return "appaudit engagement files (.appaudit/)"
    return None


# ---------------------------------------------------------------- redaction

_KEEP = 4
_SECRET_PATTERNS = [
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
    re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bwhsec_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
]
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)", re.S)
_URL_CRED = re.compile(r"(?i)(\b[a-z][a-z0-9+.\-]*://[^:/\s@]+:)([^@\s/]+)(@)")
_KV = re.compile(
    r"(?i)(\b(?:password|passwd|pwd|pass|secret|client[_-]?secret|token|access[_-]?token|"
    r"refresh[_-]?token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|authorization|"
    r"x-api-key|cookie|set-cookie|session(?:id)?)\b[\"']?\s*[:=]\s*[\"']?)"
    r"((?:bearer|basic|token)\s+)?([^\s\"'&,;]{4,})"
)
_CARD = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")


def _tail(secret: str) -> str:
    return f"[REDACTED…{secret[-_KEEP:]}]" if len(secret) > _KEEP * 2 else "[REDACTED]"


def _luhn(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def redact(text: str) -> str:
    if not text:
        return text
    text = _PRIVATE_KEY.sub("[REDACTED private key]", text)
    text = _URL_CRED.sub(lambda m: m.group(1) + "[REDACTED]" + m.group(3), text)
    for pat in _SECRET_PATTERNS:
        text = pat.sub(lambda m: _tail(m.group(0)), text)
    text = _KV.sub(lambda m: m.group(1) + (m.group(2) or "") + (m.group(3) if m.group(3).startswith("[REDACTED") else _tail(m.group(3))), text)
    text = _CARD.sub(lambda m: f"[REDACTED card…{re.sub(r'[^0-9]', '', m.group(0))[-4:]}]" if _luhn(m.group(0)) else m.group(0), text)
    return text


def clip(text: str, limit: int = MAX_FIELD) -> str:
    if text is None:
        return ""
    return text if len(text) <= limit else text[:limit] + f"…[truncated {len(text) - limit} chars]"


def as_text(obj) -> str:
    if isinstance(obj, str):
        return obj
    try:
        return json.dumps(obj, ensure_ascii=False, sort_keys=True, default=str)
    except Exception:  # noqa: BLE001
        return str(obj)


# ---------------------------------------------------------------- evidence log

def canonical(record: dict) -> str:
    body = {k: v for k, v in record.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def record_hash(record: dict) -> str:
    return hashlib.sha256(canonical(record).encode("utf-8")).hexdigest()


class _Lock:
    def __init__(self, path: Path, timeout: float = 5.0):
        self.path = str(path)
        self.timeout = timeout
        self.fd = None

    def __enter__(self):
        deadline = time.time() + self.timeout
        while True:
            try:
                self.fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                return self
            except FileExistsError:
                try:
                    if time.time() - os.path.getmtime(self.path) > 30:
                        os.unlink(self.path)
                        continue
                except OSError:
                    pass
                if time.time() > deadline:
                    raise TimeoutError(f"could not lock {self.path}")
                time.sleep(0.05)

    def __exit__(self, *exc):
        if self.fd is not None:
            os.close(self.fd)
        try:
            os.unlink(self.path)
        except OSError:
            pass
        return False


def _last_record(path: Path) -> dict | None:
    if not path.exists() or path.stat().st_size == 0:
        return None
    with open(path, "rb") as fh:
        size = fh.seek(0, os.SEEK_END)
        fh.seek(max(0, size - 131072))
        lines = [ln for ln in fh.read().splitlines() if ln.strip()]
    if not lines:
        return None
    return json.loads(lines[-1].decode("utf-8"))


def append_evidence(pdir: Path, record: dict) -> dict:
    path = pdir / EVIDENCE_REL
    path.parent.mkdir(parents=True, exist_ok=True)
    with _Lock(path.with_suffix(".lock")):
        last = _last_record(path)
        record = dict(record)
        record["seq"] = (last.get("seq", 0) + 1) if last else 1
        record["prev"] = last.get("hash", GENESIS) if last else GENESIS
        record["hash"] = record_hash(record)
        with open(path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record


def verify_log(path: Path) -> dict:
    result = {"file": str(path), "records": 0, "head_sha256": None, "verified": False, "first_error": None}
    if not path.exists():
        result["first_error"] = "log file not found"
        return result
    prev = GENESIS
    expected_seq = 1
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                result["first_error"] = f"line {lineno}: not valid JSON"
                return result
            if rec.get("seq") != expected_seq:
                result["first_error"] = f"line {lineno}: sequence {rec.get('seq')} where {expected_seq} was expected"
                return result
            if rec.get("prev") != prev:
                result["first_error"] = f"record {expected_seq}: link to previous record broken"
                return result
            if rec.get("hash") != record_hash(rec):
                result["first_error"] = f"record {expected_seq}: content does not match its hash"
                return result
            prev = rec["hash"]
            expected_seq += 1
            result["records"] += 1
    result["head_sha256"] = prev if result["records"] else None
    result["verified"] = True
    return result
