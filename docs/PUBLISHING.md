# Publishing appaudit (maintainers)

## Repository settings (GitHub → Settings and the "About" box)

| Setting | Value |
|---------|-------|
| Description | Non-destructive security assessments with Claude for systems you own or may test, plus pre-install review of plugins, skills and MCP servers: scope guard, hash-chained evidence, independent verification, regulatory flags for 9 jurisdictions, six audit-ready outputs. |
| Website | `https://github.com/unipicto/appaudit/blob/main/docs/USER-MANUAL.md` |
| Topics | `claude`, `claude-code`, `claude-plugin`, `agent-skills`, `security`, `appsec`, `pentest`, `vulnerability-assessment`, `owasp`, `cvss`, `sarif`, `compliance`, `cyber-resilience-act`, `ai-security`, `llm-security`, `mcp`, `mcp-security`, `supply-chain-security`, `iot-security`, `firmware-security` (20, the GitHub maximum) |
| Features | Issues on; Discussions optional; Wiki off (the docs live in the repository); delete head branches after merge |
| Marketplace | The Action is listed from a release: see "GitHub Marketplace" below |
| Security | Enable **Private vulnerability reporting**, Dependabot alerts, secret scanning and push protection |
| Branch protection (`main`) | Require pull requests, the `ci` workflow to pass, and linear history; no force pushes |
| Actions | Allow GitHub-owned actions; pin third-party actions to full commit SHAs |
| Releases | Created by the `release` workflow from a `v*` tag, with signed build provenance. Also move the major tag after each release so `uses: unipicto/appaudit@v4` resolves: `git tag -f v4 && git push -f origin v4` |
| Social preview | Settings → General → Social preview → upload `docs/assets/social-preview.png` (1280×640) |
| Code scanning | Optional: upload `candidates.sarif` from the self-scan with `github/codeql-action/upload-sarif` |
| Diagrams | `python3 tools/make_diagrams.py` regenerates `docs/assets/*.svg`; `rsvg-convert -w 1280 docs/assets/social-preview.svg -o docs/assets/social-preview.png` |

## GitHub Marketplace (the Action)

The Marketplace lists `action.yml` from a published release; GitHub does not review it. Needed once:
two-factor authentication on the owner account and acceptance of the GitHub Marketplace Developer
Agreement (the checkbox in the release form links to it).

1. Push the tag (`git tag v4.4.0 && git push origin v4.4.0`). The `release` workflow builds the
   packages and creates a **draft** release with them.
2. Open the draft under Releases → edit. Tick **Publish this Action to the GitHub Marketplace**,
   fix anything the form flags, choose the categories (primary: Security; second: Code quality).
3. Click **Publish release**. Then move the major tag: `git tag -f v4 && git push -f origin v4`.

`tools/release_check.py` keeps the `action.yml` description under 125 characters, which the form asks
for. To withdraw a version from the Marketplace, edit its release and clear the checkbox.

## Release checklist

1. Update the version in `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json` and every
   `skills/*/SKILL.md` (`metadata.version`); add a `## [x.y.z] - date` entry to `CHANGELOG.md`.
2. If standards or regulatory data were re-checked, update `standards-checked` in
   `skills/assess/SKILL.md`, the "Checked" lines and `regulatory/index.md`.
3. Run locally:

   ```bash
   python3 tests/run_tests.py
   python3 tools/release_check.py          # add private terms to .release-deny first (git-ignored)
   claude plugin validate .claude-plugin/plugin.json
   python3 tools/build_dist.py
   ```
4. Merge to `main`, then tag: `git tag v4.4.0 && git push origin v4.4.0`. The `release` workflow
   runs the tests, builds the packages and publishes them with `SHA256SUMS` and the changelog
   entry as release notes.
5. Users' update checks read `main`'s `.claude-plugin/plugin.json`, so they see the new version
   as soon as the merge lands. Merge the version bump only when the release is ready.

## Private terms for the release check

`tools/release_check.py` fails on anything listed in `.release-deny` (one term per line; the
file is git-ignored) or in `APPAUDIT_DENY`. Put your own name, e-mail addresses, usernames,
local paths, client names and internal hostnames there. In CI, add them as a repository secret
and pass it as `APPAUDIT_DENY`.

## Plugin directories and marketplaces

`.claude-plugin/marketplace.json` makes this repository a Claude Code marketplace
(`/plugin marketplace add unipicto/appaudit`). Submitting to other directories (Anthropic's
plugin directory, skills.sh and similar) usually needs a public repository, a license file,
a README with install instructions and a security policy; all are present.
