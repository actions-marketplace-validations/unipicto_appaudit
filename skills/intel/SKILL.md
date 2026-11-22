---
name: intel
description: >-
  Looks up CISA KEV status, FIRST EPSS v4 and NVD CVSS data for CVE IDs and returns a
  table with pre-filled CVSS v4.0 verification links. This skill should be used when the
  user runs /appaudit:intel, asks "is CVE-… exploited", "check these CVEs", "KEV status",
  "EPSS score for…", or when an appaudit assessment needs exploit data for components found.
metadata:
  version: "4.4.2"
---

# CVE threat intelligence

Arguments: one or more CVE IDs, or a path to a file with one CVE per line.

1. Validate each ID against `CVE-\d{4}-\d{4,}`; drop and list anything else.
2. Run the bundled script (standard library only; `python` if `python3` is not found):

   ```bash
   python3 "${CLAUDE_PLUGIN_ROOT}/skills/assess/scripts/vuln_intel.py" --json CVE-2024-3400 CVE-2023-4966
   ```

   For more than 20 CVEs, write them to a file and pass `--file <path>`. Add `--no-nvd`
   for a fast KEV and EPSS pass; NVD allows 5 requests per 30 seconds without the
   `NVD_API_KEY` environment variable.
3. Present one row per CVE:

   | CVE | KEV (date added, due date, ransomware use) | EPSS v4 (probability, percentile, score date) | CVSS (version, base score, vector) | Verify |

   Put the script's `calculator_url` in the Verify column when a CVSS v4.0 vector exists.
4. State plainly where data is missing. Since 15 Apr 2026 NVD enriches only prioritized
   CVEs; when NVD has no score, say so and point to the CNA or CISA-ADP data on the CVE
   record. Never fill a gap from memory.
5. Remind the reader that NVD and vendor scores are CVSS-B. A report needs CVSS-BTE
   computed for the client's environment, as set out in
   `${CLAUDE_PLUGIN_ROOT}/skills/assess/references/scoring-and-triage.md`.

If the network is unreachable, or the scope guard blocks a feed, report that the lookup
did not run. Do not retry through another tool.
