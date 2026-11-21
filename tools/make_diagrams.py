#!/usr/bin/env python3
"""Generate the diagrams in docs/assets/ (SVG, no dependencies).

  python3 tools/make_diagrams.py

The drawings are plain SVG with their own light background, so they read the same in GitHub's
light and dark themes. Edit the text here and run the script again; do not edit the SVG files.
"""
from __future__ import annotations

from html import escape
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "docs" / "assets"
FONT = "system-ui, -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif"
INK, MUTED, LINE, BG, CARD = "#0F172A", "#475569", "#CBD5E1", "#F8FAFC", "#FFFFFF"
BLUE, TEAL, VIOLET, AMBER, RED, GREEN, SLATE = "#1D4ED8", "#0F766E", "#6D28D9", "#B45309", "#B42318", "#15803D", "#334155"
TINT = {BLUE: "#EFF6FF", TEAL: "#F0FDFA", VIOLET: "#F5F3FF", AMBER: "#FFFBEB", RED: "#FEF2F2", GREEN: "#F0FDF4", SLATE: "#F1F5F9"}


class Svg:
    def __init__(self, w: int, h: int, title: str, desc: str):
        self.w, self.h = w, h
        self.parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" '
            f'aria-labelledby="t d" font-family="{FONT}">',
            f'<title id="t">{escape(title)}</title><desc id="d">{escape(desc)}</desc>',
            '<defs>' + "".join(
                f'<marker id="a{c[1:]}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
                f'<path d="M0,0 L10,5 L0,10 z" fill="{c}"/></marker>' for c in (SLATE, BLUE, TEAL, VIOLET, AMBER, RED, GREEN)) + '</defs>',
            f'<rect width="{w}" height="{h}" rx="16" fill="{BG}" stroke="{LINE}"/>',
        ]

    def rect(self, x, y, w, h, fill=CARD, stroke=LINE, r=10, sw=1.2, dash=None):
        d = f' stroke-dasharray="{dash}"' if dash else ""
        self.parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{d}/>')

    def text(self, x, y, s, size=14, weight=400, fill=INK, anchor="start", italic=False):
        st = ' font-style="italic"' if italic else ""
        self.parts.append(f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{weight}" fill="{fill}" text-anchor="{anchor}"{st}>{escape(s)}</text>')

    def lines(self, x, y, items, size=13, fill=MUTED, gap=None, anchor="start", weight=400):
        gap = gap or round(size * 1.45)
        for i, s in enumerate(items):
            self.text(x, y + i * gap, s, size, weight, fill, anchor)
        return y + len(items) * gap

    def wrap(self, s, width, size):
        per = max(8, int(width / (size * 0.53)))
        out, cur = [], ""
        for word in s.split():
            if len(cur) + len(word) + 1 > per and cur:
                out.append(cur)
                cur = word
            else:
                cur = (cur + " " + word).strip()
        if cur:
            out.append(cur)
        return out

    def card(self, x, y, w, h, title, body=(), color=BLUE, size=13, title_size=15, tint=True):
        self.rect(x, y, w, h, TINT[color] if tint else CARD, color, 10, 1.4)
        self.rect(x, y, 6, h, color, color, 3, 0)
        self.text(x + 18, y + 24, title, title_size, 700, INK)
        yy = y + 24 + round(title_size * 1.5)
        for b in body:
            for ln in self.wrap(b, w - 34, size):
                self.text(x + 18, yy, ln, size, 400, MUTED)
                yy += round(size * 1.42)
        return yy

    def pill(self, x, y, label, color=BLUE, size=12, pad=10):
        w = int(len(label) * size * 0.56) + 2 * pad
        self.rect(x, y, w, size + 12, color, color, (size + 12) // 2, 0)
        self.text(x + w / 2, y + size + 2, label, size, 700, "#FFFFFF", "middle")
        return w

    def arrow(self, x1, y1, x2, y2, color=SLATE, label=None, dash=None, lx=None, ly=None, size=12):
        d = f' stroke-dasharray="{dash}"' if dash else ""
        self.parts.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="1.8"{d} marker-end="url(#a{color[1:]})"/>')
        if label:
            self.text(lx if lx is not None else (x1 + x2) / 2, ly if ly is not None else (y1 + y2) / 2 - 6, label, size, 600, color, "middle")

    def path(self, d, color=SLATE, dash=None):
        ds = f' stroke-dasharray="{dash}"' if dash else ""
        self.parts.append(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="1.8"{ds} marker-end="url(#a{color[1:]})"/>')

    def header(self, title, sub):
        self.text(36, 48, title, 24, 800, INK)
        self.text(36, 74, sub, 14, 400, MUTED)

    def footer(self, s="github.com/unipicto/appaudit"):
        self.text(self.w - 30, self.h - 18, s, 11, 400, "#94A3B8", "end")

    def save(self, name):
        OUT.mkdir(parents=True, exist_ok=True)
        (OUT / name).write_text("\n".join(self.parts) + "\n</svg>\n", encoding="utf-8", newline="\n")


def overview():
    s = Svg(1200, 600, "appaudit overview", "What you give appaudit, what it does, and what you get back.")
    s.header("appaudit at a glance", "Non-destructive security assessments with Claude, for systems you own or have the owner's written permission to test")
    # left column
    s.text(36, 122, "WHAT YOU GIVE IT", 12, 700, BLUE)
    items = ["Web apps and APIs", "Dependencies, CI/CD, infrastructure code", "Mobile and smart-device apps", "Firmware images",
             "AI features and agents", "Plugins, skills, MCP servers", "Rules files, browser extensions"]
    y = 138
    for it in items:
        s.rect(36, y, 300, 40, CARD, LINE, 8)
        s.rect(36, y, 5, 40, BLUE, BLUE, 2, 0)
        s.text(54, y + 25, it, 14, 500)
        y += 50
    s.text(36, y + 14, "Source code, packages or a live staging system", 12, 400, MUTED, italic=True)
    # centre
    s.text(392, 122, "WHAT IT DOES", 12, 700, TEAL)
    steps = [("0", "Update check", "Tells you first if a newer release exists", SLATE),
             ("1", "Permission and scope", "You record the owner's permission, hosts, window", AMBER),
             ("2", "Parallel review", "Six read-only specialist agents and an offline scanner", BLUE),
             ("3", "Validation and scoring", "Benign proofs in scope; CVSS v4.0, SSVC, EPSS, KEV", TEAL),
             ("4", "Independent verification", "A separate agent re-checks every finding", VIOLET),
             ("5", "Regulatory flags", "9 jurisdictions; client or counsel decides", RED)]
    y = 138
    for n, t, d, c in steps:
        s.rect(392, y, 400, 58, TINT[c], c, 10, 1.4)
        s.parts.append(f'<circle cx="422" cy="{y + 29}" r="15" fill="{c}"/>')
        s.text(422, y + 34, n, 14, 800, "#FFFFFF", "middle")
        s.text(448, y + 25, t, 15, 700)
        s.text(448, y + 44, d, 12.5, 400, MUTED)
        if n != "5":
            s.arrow(592, y + 58, 592, y + 68, SLATE)
        y += 68
    # right
    s.text(848, 122, "WHAT YOU GET, EVERY RUN", 12, 700, VIOLET)
    outs = [("brief.md", "one page for management and counsel"), ("report.md", "proof, root cause, fix, re-test"),
            ("findings.json", "single source of truth"), ("findings.sarif", "CI and code scanning"),
            ("findings-register.xlsx", "owners, due dates, status"), ("evidence-bundle.zip", "hashes for auditors")]
    y = 138
    for n, d in outs:
        s.rect(848, y, 316, 50, CARD, LINE, 8)
        s.rect(848, y, 5, 50, VIOLET, VIOLET, 2, 0)
        s.text(866, y + 22, n, 14, 700)
        s.text(866, y + 40, d, 12, 400, MUTED)
        y += 58
    s.text(848, y + 12, "Extension reviews add an install decision,", 12, 400, MUTED, italic=True)
    s.text(848, y + 29, "a capabilities table and a baseline.", 12, 400, MUTED, italic=True)
    s.arrow(340, 330, 386, 330, BLUE)
    s.arrow(796, 330, 842, 330, VIOLET)
    s.rect(392, 556, 400, 28, CARD, LINE, 14)
    s.text(592, 575, "Not a certification. Not legal advice. Not a sandbox.", 12.5, 600, SLATE, "middle")
    s.footer()
    s.save("overview.svg")


def workflow():
    s = Svg(1200, 664, "appaudit workflow", "Who does what in an assessment: main agent, parallel reviewers, scripts, verifier and regulatory mapper.")
    s.header("How an assessment runs", "No agent grades its own work: finding, verifying and legal mapping are done by different agents; merging and reporting are code")
    lanes = [("Main agent", "talks to you, touches targets", BLUE, 104), ("Reviewer agents", "read-only, in parallel", TEAL, 236),
             ("Scripts", "deterministic, no model", SLATE, 368), ("Checking agents", "read-only, independent", VIOLET, 500)]
    for name, sub, c, y in lanes:
        s.rect(30, y, 1140, 112, TINT[c], LINE, 10, 1)
        s.text(46, y + 26, name, 14, 800, c)
        s.text(46, y + 44, sub, 11.5, 400, MUTED)
    bw, bh = 150, 62

    def box(x, lane_y, t, d, c):
        y = lane_y + 40
        s.rect(x, y, bw, bh, CARD, c, 9, 1.5)
        s.text(x + bw / 2, y + 25, t, 13.5, 700, INK, "middle")
        for i, ln in enumerate(s.wrap(d, bw - 12, 11)[:2]):
            s.text(x + bw / 2, y + 42 + i * 13, ln, 11, 400, MUTED, "middle")
        return x, y

    xs = [200, 362, 524, 686, 848, 1010]
    a = box(xs[0], 104, "Update check", "first line of the reply", BLUE)
    b = box(xs[1], 104, "Scope", "permission, hosts, window", BLUE)
    c = box(xs[2], 104, "Recon", "map the target, assign files", BLUE)
    e = box(xs[4], 104, "Validate, score", "benign proofs in scope", BLUE)
    r = box(xs[3], 236, "6 reviewers", "one per module, side by side", TEAL)
    sc = box(xs[2], 368, "Extension scan", "scan_extension.py", SLATE)
    m = box(xs[3], 368, "Merge", "one finding per root cause", SLATE)
    bo = box(xs[5], 368, "Build outputs", "validates, then 6 files", SLATE)
    v = box(xs[4], 500, "Verifier", "evidence only, starts from doubt", VIOLET)
    rm = box(xs[5], 500, "Regulatory mapper", "two-tier flags", VIOLET)
    mid = lambda p: (p[0] + bw / 2, p[1] + bh / 2)
    s.arrow(a[0] + bw, mid(a)[1], b[0] - 2, mid(b)[1], BLUE)
    s.arrow(b[0] + bw, mid(b)[1], c[0] - 2, mid(c)[1], BLUE)
    s.path(f"M{c[0] + bw} {mid(c)[1] + 10} L{r[0] + 40} {mid(c)[1] + 10} L{r[0] + 40} {r[1] - 2}", TEAL)
    s.arrow(mid(c)[0], c[1] + bh, mid(sc)[0], sc[1] - 2, SLATE, dash="5 4")
    s.arrow(sc[0] + bw, mid(sc)[1], m[0] - 2, mid(m)[1], SLATE)
    s.arrow(mid(r)[0], r[1] + bh, mid(m)[0], m[1] - 2, TEAL)
    s.path(f"M{m[0] + bw} {mid(m)[1] - 12} L{mid(e)[0] - 20} {mid(m)[1] - 12} L{mid(e)[0] - 20} {e[1] + bh + 2}", BLUE)
    s.path(f"M{mid(e)[0] + 20} {e[1] + bh} L{mid(e)[0] + 20} {v[1] - 2}", VIOLET)
    s.arrow(v[0] + bw, mid(v)[1], rm[0] - 2, mid(rm)[1], VIOLET)
    s.arrow(mid(rm)[0], rm[1], mid(bo)[0], bo[1] + bh + 2, SLATE)
    s.rect(xs[5], 144, bw, bh, "#0F172A", "#0F172A", 9)
    s.text(xs[5] + bw / 2, 169, "Six outputs", 13.5, 700, "#FFFFFF", "middle")
    s.text(xs[5] + bw / 2, 187, "+ hashes, re-test delta", 11, 400, "#CBD5E1", "middle")
    s.arrow(mid(bo)[0], bo[1], mid(bo)[0], 144 + bh + 2, SLATE)
    s.text(mid(c)[0] + 8, 228, "extensions", 10.5, 600, SLATE)
    s.text(46, 640, "Scope guard and evidence log (hooks) run under every step in Claude Code and Cowork.", 12, 400, MUTED, italic=True)
    s.footer()
    s.save("workflow.svg")


def extension_review():
    s = Svg(1200, 520, "appaudit extension review", "How a plugin, skill or MCP server is reviewed before installation.")
    s.header("Reviewing a plugin, skill or MCP server before you install it", "/appaudit:extension reads a copy. The extension is never installed, enabled or run")
    y, h, w = 112, 150, 196
    xs = [36, 268, 500, 732, 964]
    s.card(xs[0], y, w, h, "1. A copy", ["Folder or archive: plugin, skill, MCP config, rules file, browser extension.", "Or everything installed here."], SLATE)
    s.card(xs[1], y, w, h, "2. Offline scanner", ["Code, not a model: cannot be persuaded.", "64 rules, SHA-256 of every file, hidden text decoded."], BLUE)
    s.card(xs[2], y, w, h, "3. Reviewer agent", ["Read-only. Does each capability fit the stated purpose?", "Plain-language intent, toxic combinations."], TEAL)
    s.card(xs[3], y, w, h, "4. Verifier agent", ["Checks every candidate against the file.", "Text in the package never lowers a verdict."], VIOLET)
    s.card(xs[4], y, w, h, "5. You decide", ["An install decision with reasons and conditions.", "Six outputs plus the capabilities table."], AMBER)
    for i in range(4):
        s.arrow(xs[i] + w + 2, y + h / 2, xs[i + 1] - 4, y + h / 2, SLATE)
    # capabilities strip
    s.text(36, 300, "FIRST THING YOU SEE: WHAT THIS EXTENSION CAN DO", 12, 700, BLUE)
    caps = ["Runs code automatically", "Reaches the network", "Reads credential files", "Changes settings or start-up",
            "Loosens permission prompts", "Holds embedded secrets", "Has files nobody could inspect"]
    x = 36
    for cap in caps:
        wd = int(len(cap) * 6.6) + 22
        if x + wd > 1164:
            break
        s.rect(x, 312, wd, 30, CARD, LINE, 15)
        s.text(x + wd / 2, 332, cap, 12, 500, INK, "middle")
        x += wd + 8
    # decisions
    s.text(36, 384, "THE RECOMMENDATION", 12, 700, AMBER)
    d = [("Do not install", "A verified Critical or High finding, or signs of malicious intent", RED),
         ("Install only after conditions", "For example: pin the version, remove a hook, narrow a permission", AMBER),
         ("No blocking issue found", "Never called safe: static review cannot see run-time behaviour", GREEN)]
    x = 36
    for t, sub, c in d:
        s.rect(x, 396, 366, 64, TINT[c], c, 10, 1.4)
        s.text(x + 16, 421, t, 14.5, 700, c)
        s.text(x + 16, 442, sub, 11.5, 400, MUTED)
        x += 381
    s.text(36, 492, "Keep the scan folder: on the next update, --baseline flags new hosts, new automatic commands, new permission changes and changed instructions.", 12, 400, MUTED, italic=True)
    s.footer()
    s.save("extension-review.svg")


def scope_guard():
    s = Svg(1200, 560, "appaudit scope guard", "How the scope guard answers each tool call: deny, ask or pass.")
    s.header("The scope guard: deny, ask or pass", "A hook that checks every Bash, WebFetch, file-write and MCP call before it runs. A guard rail, not a sandbox")
    s.rect(36, 110, 190, 76, CARD, SLATE, 10, 1.5)
    s.text(131, 142, "Tool call", 15, 700, INK, "middle")
    s.text(131, 162, "from Claude or a sub-agent", 11.5, 400, MUTED, "middle")
    s.rect(290, 110, 240, 76, TINT[BLUE], BLUE, 10, 1.5)
    s.text(410, 142, "Engagement open?", 15, 700, INK, "middle")
    s.text(410, 162, ".appaudit/scope.json", 11.5, 400, MUTED, "middle")
    s.arrow(228, 148, 286, 148, SLATE)
    # no branch
    s.rect(600, 110, 564, 76, CARD, LINE, 10)
    s.text(618, 136, "No engagement", 13, 700, SLATE)
    s.text(618, 156, "A scanning tool (nmap, sqlmap, nuclei ...) starts:", 12.5, 400, MUTED)
    s.pill(900, 142, "ASK", AMBER)
    s.text(618, 175, "Anything else:", 12.5, 400, MUTED)
    s.pill(706, 162, "PASS", GREEN)
    s.arrow(532, 148, 596, 148, SLATE, "no", lx=564, ly=140)
    s.arrow(410, 188, 410, 226, BLUE, "yes", lx=432, ly=212)
    cols = [(36, "DENY", RED, ["Host is out of scope or not in scope", "In scope, but outside the testing window",
                               "Any target while the mode is static", "An in-scope name pointed at another address (--resolve, Host header)",
                               "Scope file unreadable or guard error (fails closed)"]),
            (420, "ASK THE USER", AMBER, ["Possible host given to a program the guard does not know",
                                          "Targets in a file it cannot read, or an SSH alias", "Command built at run time (pipe to shell, eval, decode)",
                                          "Any change to the scope file or evidence log", "Python missing while an engagement file exists"]),
            (804, "PASS", GREEN, ["In-scope host, active mode, inside the window", "Support hosts: threat-intel feeds, standards bodies, registries",
                                  "Calls that reach no host", "The plugin's own scripts",
                                  "Still subject to Claude's normal permission prompts"])]
    for x, t, c, rows in cols:
        s.rect(x, 232, 360, 232, TINT[c], c, 12, 1.5)
        s.pill(x + 16, 246, t, c, 13)
        y = 296
        for row in rows:
            s.parts.append(f'<circle cx="{x + 24}" cy="{y - 4}" r="3" fill="{c}"/>')
            for i, ln in enumerate(s.wrap(row, 310, 12.5)):
                s.text(x + 36, y + i * 16, ln, 12.5, 400, INK)
            y += 16 * len(s.wrap(row, 310, 12.5)) + 9
    s.rect(36, 480, 1128, 44, CARD, LINE, 10)
    s.text(54, 507, "Evidence log:", 13, 700, INK)
    s.text(146, 507, "every Bash, WebFetch and network-reaching MCP call, and every block, is written to a hash-chained, secret-redacted log.", 12.5, 400, MUTED)
    s.text(36, 544, "Not seen: a program that hides or computes its own target, server redirects, DNS tricks. Restrict outbound traffic at the OS or firewall when that matters.", 11.5, 400, MUTED, italic=True)
    s.footer()
    s.save("scope-guard.svg")


def coverage():
    s = Svg(1200, 580, "appaudit coverage", "Product types appaudit covers, with standards and whether live testing is possible.")
    s.header("What appaudit covers", "Static review of what you hand over is always possible; live testing only inside a scope you recorded")
    rows = [("Websites and web apps", "OWASP Top 10:2025, ASVS 5.0.0", "full", True, BLUE),
            ("APIs: REST, GraphQL, gRPC", "OWASP API Security Top 10 2023", "full", True, BLUE),
            ("Supply chain, CI/CD, infrastructure code", "NIST SSDF, SLSA, CycloneDX / SPDX", "full", False, BLUE),
            ("Mobile apps: iOS, Android", "OWASP MASVS 2.1, MASTG 2.0", "full", True, TEAL),
            ("Smart-device and IoT apps", "MASVS, ISVS 1.0, EN 18031", "full", True, TEAL),
            ("Embedded devices and firmware", "ISVS 1.0, ETSI EN 303 645, CRA", "full (image)", False, TEAL),
            ("AI features, chatbots, agents", "OWASP LLM Top 10 2026, Agentic ASI01-10", "full", True, VIOLET),
            ("Plugins, skills, MCP servers, hooks", "OWASP Agentic Skills AST01-10, MCP best practices", "full (static)", False, VIOLET),
            ("Agent rules and settings in repositories", "CLAUDE.md, AGENTS.md, .mcp.json, Cursor / Copilot rules", "full (static)", False, VIOLET),
            ("Browser extensions, custom GPTs, desktop apps", "Manifest V3 model, LLM Top 10, CWE Top 25", "partial", False, SLATE)]
    s.text(54, 118, "PRODUCT", 11.5, 700, MUTED)
    s.text(470, 118, "MAIN STANDARDS", 11.5, 700, MUTED)
    s.text(930, 118, "COVERAGE", 11.5, 700, MUTED)
    s.text(1080, 118, "LIVE TESTS", 11.5, 700, MUTED)
    y = 130
    for name, std, cov, live, c in rows:
        s.rect(36, y, 1128, 34, CARD, LINE, 8)
        s.rect(36, y, 5, 34, c, c, 2, 0)
        s.text(54, y + 22, name, 13.5, 600)
        s.text(470, y + 22, std, 12.5, 400, MUTED)
        s.pill(930, y + 6, cov, GREEN if cov.startswith("full") else AMBER, 11.5, 9)
        s.text(1080, y + 22, "in scope" if live else "static only", 12.5, 500, BLUE if live else MUTED)
        y += 39
    s.text(36, y + 18, "Not covered:", 12.5, 700, RED)
    s.text(122, y + 18, "internal network and Active Directory tests, cloud-account reviews through cloud APIs, OT/ICS, physical and social engineering,", 12.5, 400, MUTED)
    s.text(122, y + 36, "denial of service, red-team operations. Reports list what was not tested, so a missing finding is never read as a pass.", 12.5, 400, MUTED)
    s.footer()
    s.save("coverage.svg")


def social():
    s = Svg(1280, 640, "appaudit", "Security assessments with Claude: scope guard, independent verification, audit-ready outputs.")
    s.parts[-1] = f'<rect width="1280" height="640" fill="#0B1220"/>'
    s.parts.append('<rect x="64" y="72" width="10" height="150" rx="5" fill="#3B82F6"/>')
    s.text(100, 150, "appaudit", 92, 800, "#FFFFFF")
    s.text(104, 206, "Security assessments with Claude", 34, 500, "#93C5FD")
    y = 300
    for t in ["Web apps, APIs, mobile, firmware, AI agents",
              "Plugins, skills and MCP servers checked before you install them",
              "Enforced scope  ·  independent verification  ·  six audit-ready outputs"]:
        s.text(104, y, t, 27, 400, "#E2E8F0")
        y += 48
    x = 104
    for label, c in (("DENY", "#DC2626"), ("ASK", "#D97706"), ("PASS", "#16A34A")):
        s.rect(x, 478, 130, 50, c, c, 25, 0)
        s.text(x + 65, 511, label, 22, 800, "#FFFFFF", "middle")
        x += 146
    s.text(560, 511, "a guard rail on every tool call", 22, 400, "#94A3B8")
    s.text(104, 592, "github.com/unipicto/appaudit   ·   Apache-2.0   ·   for systems you own or may test", 20, 400, "#64748B")
    s.save("social-preview.svg")


if __name__ == "__main__":
    for f in (overview, workflow, extension_review, scope_guard, coverage, social):
        f()
    print("wrote", ", ".join(sorted(p.name for p in OUT.glob("*.svg"))))
