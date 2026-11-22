# findings.json — canonical schema (`appaudit-findings/1`)

`findings.json` is the single source of truth for every output. `scripts/build_outputs.py`
validates it, refuses to build on errors, and lists warnings in the report appendix.
A complete example: `findings-example.json` in this folder. A machine-readable JSON Schema
(draft 2020-12): `findings.schema.json` in this folder. The builder's own checks are stricter
than the schema (for example, verifier verdicts in plugin runs and KEV vs. SSVC).

## Top level

| Field | Required | Notes |
|-------|----------|-------|
| `schema` | yes | `"appaudit-findings/1"` |
| `engagement` | yes | See below |
| `summary` | no | `posture` (Critical/High/Medium/Low; computed if absent), `assessor_summary` (≤5 sentences), `decisions_needed[]`, `install_decision` (extension reviews: `{ "decision": "do_not_install|install_with_conditions|no_blocking_issue_found", "reason": "", "conditions": [] }`, printed at the top of the brief) |
| `findings[]` | yes | May be empty |
| `verified_not_applicable[]` | no | `{ "item": "", "reason": "" }` |
| `evidence` | no | `raw_location`, `access`, `secrets_found` (count), `rotation_recommended_for[]` (systems, never values) |

## `engagement`

| Field | Required | Notes |
|-------|----------|-------|
| `name` | yes | Short slug-friendly name; used for the output folder |
| `client`, `target`, `date`, `assessor` | `date` yes | `date` = ISO `YYYY-MM-DD` |
| `authorization` | yes | `{ "basis": "owner|signed-scope|rules-of-engagement|bug-bounty|obtained-copy|none", "reference": "" }`. `obtained-copy` = static review of a copy of a distributed artifact (extension, app, firmware image); no system is tested |
| `mode` | yes | `static` or `active` |
| `window` | no | `{ "start": "", "end": "" }` |
| `scope` | no | `{ "in": [], "out": [] }` |
| `capabilities_used[]` | no | `static review`, `shell`, `outbound HTTP`, `browser`, `device` |
| `threat_intel_refreshed` | no | Date or `null` |
| `jurisdiction_profile` | no | As in `regulatory/index.md` §2 |
| `jurisdictions_assessed[]`, `jurisdictions_not_assessed[]` | no | ISO codes; `not_assessed` is printed in every brief |
| `not_tested[]` | no | Areas not tested, so absence of a finding is not read as a pass |

## `findings[]`

| Field | Required | Values / notes |
|-------|----------|----------------|
| `id` | yes | Unique, e.g. `AA-001` |
| `title` | yes | — |
| `severity` | yes | `Critical`, `High`, `Medium`, `Low`, `Informational`. Must match the CVSS-BTE band when a score is given (warning otherwise) |
| `confidence` | yes | `Confirmed`, `Likely`, `Informational` |
| `verifier` | no* | `{ "verdict": "Confirmed|Likely|Needs evidence|Rejected", "notes": "" }`. *Plugin runs: required; a confidence above the verdict is an error |
| `status` | no | `open` (default), `fixed`, `risk_accepted`, `false_positive` |
| `asset` | no | System or component name |
| `location` | no | `{ "kind": "file|url|host|binary|prompt|config|other", "uri": "", "start_line": 1, "end_line": 1, "description": "" }`. SARIF includes only `kind: file` |
| `cwe[]`, `owasp[]`, `asvs[]`, `opencre[]`, `cve[]` | no | e.g. `CWE-639`, `A01:2025`, `v5.0.0-8.2.1` |
| `cvss_v4` | no | `{ "nomenclature": "CVSS-BTE", "vector": "CVSS:4.0/…", "score": 8.7, "calculator_url": "" }`. Score from the FIRST calculator; `calculator_url` is filled in if missing |
| `ssvc` | no | `{ "exploitation": "none|public_poc|active", "automatable": "yes|no", "technical_impact": "partial|total", "mission_wellbeing": "low|medium|high", "decision": "Track|Track*|Attend|Act" }` |
| `epss` | no | `{ "probability": 0.0, "percentile": 0.0, "date": "", "model": "v4" }` |
| `kev` | no | `{ "listed": false, "date_added": null, "due_date": null }`. KEV-listed with SSVC below Attend is an error |
| `description`, `root_cause`, `impact` | no | Plain text |
| `proof_steps[]` | no | Benign steps, secrets redacted |
| `remediation` | no | `{ "summary": "", "patch": "", "language": "", "regression_note": "" }` |
| `retest` | no | `{ "action": "", "expected": "", "result": "", "date": "" }` |
| `timeline` | no | `{ "basis": "KEV dueDate (BOD 26-04)|PCI DSS 6.3.3|organisation-defined", "due": "YYYY-MM-DD" }` |
| `owner` | no | Person or team |
| `regulatory[]` | no | As in `regulatory/index.md` §5. `tier` must be `may_trigger_now` or `readiness`; `decided_by` must be `client/counsel` |
| `disclosure[]` | no | `{ "channel": "", "deadline": "", "conflict": "", "decided_by": "client/counsel" }` |
| `evidence_refs[]` | no | `{ "log_seq": 12, "note": "" }`, pointing at `.appaudit/evidence/evidence.jsonl` |
| `sources[]` | no | Which reviewer agents or passes reported it (filled by `merge_candidates.py`) |
| `merge_notes[]` | no | Duplicates merged into this finding |
| `rule` | no | Detection rule behind a scanner candidate, e.g. `EXT-I02` (`scan_extension.py`); rule catalogue in `module-agent-extensions.md` |
