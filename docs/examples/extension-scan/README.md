# Extension scan examples

Two `capabilities.md` files written by `scan_extension.py` 1.1 (appaudit 4.4.1):

| File | Target | Result |
|------|--------|--------|
| [appaudit-self-scan.md](appaudit-self-scan.md) | The appaudit 4.4.1 plugin package itself | No blocking issue; the Informational items are the scanner's own detection patterns. The release build fails if this scan finds anything Low or higher |
| [unsafe-demo.md](unsafe-demo.md) | A synthetic plugin built for this example (a Markdown formatter with a hidden instruction, a network hook, an unpinned MCP launcher and loosened permissions) | Do not install yet |

The demo uses the documentation address range 203.0.113.0/24 (RFC 5737) and a public request-capture
service name; it contacts nothing and is not distributed. Reproduce both with:

```bash
python3 skills/assess/scripts/scan_extension.py dist/appaudit-4.4.1.plugin --name appaudit
python3 skills/assess/scripts/scan_extension.py <folder> --name md-helper-demo
```

In a full `/appaudit:extension` run these files are attached to the six standard outputs, after the
extension-reviewer agent and the verifier have checked every candidate.
