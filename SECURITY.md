# Security policy

appaudit is itself security tooling: it runs hooks on every tool call and asks an AI agent to
act within an engagement scope. Problems in it can matter, so please report them privately.

## Reporting a vulnerability in appaudit

Use **GitHub private vulnerability reporting**: repository → *Security* → *Report a
vulnerability*. Please do not open a public issue for a security problem.

Include the affected version (`.claude-plugin/plugin.json`), the component (scope guard,
evidence log, output builder, a skill or agent), steps to reproduce with benign data, and the
impact you expect. You will get an acknowledgement within 7 days and a fix or mitigation plan
within 30 days for confirmed issues. Coordinated disclosure: we publish an advisory after a
fixed release is available, crediting you unless you prefer otherwise.

In scope, for example:

- A tool call that contacts a host outside the scope without the scope guard blocking it,
  where the target is visible in the command or URL (see the documented limits in
  docs/HOW-IT-WORKS.md for what the guard cannot see).
- Changing `.appaudit/scope.json` or the evidence log without the approval prompt.
- An evidence-log change that `verify_evidence.py` does not detect.
- A secret or personal data that the redaction misses in a common format.
- Prompt-injection paths where target content makes the skills or agents ignore the
  authorization gate.
- Output-builder issues: path traversal, overwriting files outside the output folder.

Out of scope: findings that need the attacker to already control the user's machine or the
plugin files; missing checks in the assessment modules (open a normal issue instead).

## Supported versions

Only the latest release receives fixes. The update check that starts every assessment tells
users when a newer release exists.

## Verifying a release

Every GitHub release lists SHA-256 hashes (`SHA256SUMS`). Verify the file you downloaded
before installing it:

```bash
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify appaudit-*.plugin --repo unipicto/appaudit   # signed build provenance
```

The build is reproducible: the same commit gives byte-identical packages on Linux, macOS and
Windows with Python 3.9 or later, and CI checks this on every push. To confirm that a release was
built from the published source, check out its tag, run `python tools/build_dist.py` and compare
`dist/SHA256SUMS` with the release's `SHA256SUMS`. They must match exactly.
