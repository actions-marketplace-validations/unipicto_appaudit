# Threat model — what appaudit protects against, and what it does not

appaudit is a security tool that runs inside an AI agent. This page states plainly what its controls
are worth, so that nobody relies on them for more. It is the result of the project's own critical
review (version 4.4.1); report anything it misses through [SECURITY.md](../SECURITY.md).

## What is protected, and from what

| Asset | Threat | Control | Strength |
|-------|--------|---------|----------|
| Systems outside the engagement | The agent contacts a host it has no permission to test (wrong target, redirect, pivot, typo) | Scope guard: deny / ask (see [HOW-IT-WORKS.md](HOW-IT-WORKS.md)) | Guard rail. Stops mistakes and plain instructions; not a determined process |
| The record of permission and scope | The agent, or text it read, changes the scope to widen it | Every change to the scope file asks the user | Strong for file tools; pattern-based for shell commands |
| The client's trust in findings | A finding its author believes but the evidence does not support | Independent verifier agent; the builder refuses a confidence above the verdict | Strong against overstatement; the verifier reads only what is cited |
| The integrity of evidence | Records changed after the fact | Hash chain, SHA-256 manifest, head hash in the brief | Shows partial edits. A full rebuild needs the head hash to be noted elsewhere |
| The assessor's machine | An extension under review runs code or steers the agent | The scanner never executes the target; reviewer agents are read-only and told that package text is data | Strong for execution. Persuasion of a model can never be fully excluded |
| The user's decisions | A clean scan read as "safe"; a flag read as legal advice | Wording rules: never "safe", never "notification required", never a certification | Depends on the reader |
| Users of appaudit itself | A tampered or malicious appaudit package | Reproducible build, SHA-256 sums, signed build provenance, self-scan gate, pinned CI actions | Strong if the user verifies the download |

## Known bypasses of the scope guard

The guard reads the command line; it does not watch the network. With an engagement open:

| Case | What happens |
|------|--------------|
| URL or host given to a known network tool, WebFetch or an MCP tool | Checked; denied when out of scope |
| Host given to an unknown program, script, container or package runner | Asks, if the argument looks like a host name or address |
| Targets in a list file | Checked if the file is readable; otherwise asks |
| Command built at run time (pipe into a shell, `eval`, decoding) | Asks |
| **A script or binary that contains or computes its own target** | **Not seen** |
| **A redirect from an in-scope server to another host** | **Not seen** (the tool follows it, not the guard) |
| **An in-scope host name that resolves to an out-of-scope address** | **Not seen** (no DNS resolution, by design) |
| **A host name with an unusual ending passed to an unknown program** | **Not seen** (only two-letter and common endings are treated as hosts there) |
| **Writing the scope file through a path that hides its name** | **Not seen** for shell commands |
| **Tools that do not appear in the hook matcher** (a future tool type) | **Not seen** until the matcher is updated |

If any of these matters for an engagement, restrict outbound traffic at the operating system,
container or firewall: allow only the in-scope addresses and the support hosts.

## Prompt injection against the assessor

Everything appaudit reads may be written by an adversary: web pages of the target, source code
comments, tool output, the files of an extension under review. Controls: the skills and agents
state that such text is data; reviewer and verifier agents have no tools that act; the scope guard
and the approval prompts stand between an injected instruction and a network call; the scanner is
code, not a model, and cannot be persuaded. Residual risk: a model can still be influenced in what
it writes (a finding left out, a rating lowered). The verifier, the deterministic scanner results
and a human reading the report are the checks on that.

## Limits of the extension scanner

- Static only. Nothing is executed, so behaviour that appears only at run time is not seen.
- Pattern rules find known shapes. Harmful intent in ordinary words, split across files, or in a
  language the rules do not cover can pass; the reviewer agent and a human must read for it.
- Remote MCP servers send tool descriptions at run time, and package runners download code later.
- Severity adjustments (documentation, tests, quoted examples) can be abused by an author who
  dresses an instruction up as an example. They lower a rating by steps; they never remove a result.
- Files over the size limit, binaries and encrypted or deeply nested archives are reported as not inspected.

## What appaudit does not try to do

Exploitation, persistence, evasion, denial of service; legal advice; certification; proof that
untested areas are secure; verification that the permission to test is genuine.

## Data appaudit keeps

`.appaudit/` in the project: the scope, the evidence log (commands, redacted excerpts of responses
of up to 4,000 characters, hashes), candidates, reports. Redaction is pattern-based and can miss
unusual secrets or personal data. Keep the folder out of version control, store it where the
engagement's data-handling terms say, and delete it when the retention period ends. appaudit sends
nothing anywhere except the update check and the threat-intelligence lookups you ask for.
