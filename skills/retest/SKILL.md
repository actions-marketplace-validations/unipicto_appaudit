---
name: retest
description: >-
  Compares an appaudit re-test with an earlier assessment of the same target and reports
  which findings were fixed, which are new, which persist (with severity or SSVC changes)
  and which were risk-accepted, plus changes to regulatory flags. This skill should be used
  when the user runs /appaudit:retest or says "re-test", "verify the fixes", "compare with
  the last assessment", "what changed since the previous report", or "close out findings".
metadata:
  version: "4.4.1"
---

# Re-test comparison

Arguments: optional path to the earlier run folder or its `findings.json`. Without one, use
the most recent folder under `.appaudit/reports/` other than the current run.

## 1. Re-test the open findings

For every finding that was open in the earlier run, repeat its `retest.action` within the
current scope and authorization (run `/appaudit:scope` first if the engagement was closed).
Record the outcome in `retest.result` and `retest.date`, and set `status` to `fixed`,
`open` or `risk_accepted` (the last only on the client's written decision). Keep the same
finding IDs. Add newly found issues as new findings. Send changed findings to the
`appaudit:verifier` agent as in `/appaudit:report`.

## 2. Build the outputs with the comparison

```bash
python3 -I "${CLAUDE_PLUGIN_ROOT}/skills/assess/scripts/build_outputs.py" --findings .appaudit/findings.json --scope .appaudit/scope.json --evidence .appaudit/evidence/evidence.jsonl --out .appaudit/reports --plugin-root "${CLAUDE_PLUGIN_ROOT}" --update-source "${user_config.update_source}" --previous "<earlier run folder>/findings.json"
```

Run it as one command, exactly in this form. The run folder then also holds `delta.md` and
`delta.json`, and the brief and report carry a re-test line. To compare two existing runs
without rebuilding, use `compare_runs.py --previous A/findings.json --current B/findings.json`.

## 3. Report back

Give the totals (fixed, new, persisting, risk-accepted, not re-tested), every persisting
finding whose severity or SSVC decision went up, and every regulatory flag that was added.
A finding counts as fixed only when its status is `fixed` with a re-test result; a finding
missing from the current run is listed as "not re-tested", never as fixed.
