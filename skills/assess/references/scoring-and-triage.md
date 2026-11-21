# Scoring & Triage

Two separate questions, two separate standards:

- **Severity** — how bad is the flaw? → **CVSS v4.0** (FIRST), reported with its full vector.
- **Priority** — what should the client do, and how fast? → **CISA SSVC** decision, with
  **EPSS v4** and **CISA KEV** as inputs.

Do not invent band-bumping rules. CVSS v4's Threat metric already captures exploitation;
adding a further "+1 band if exploited" double-counts it and cannot be cited to any authority.

---

## 1. Severity — CVSS v4.0

Use FIRST nomenclature for which metric groups were applied:

| Label | Metric groups | When |
|-------|---------------|------|
| CVSS-B | Base | Minimum; vendor/NVD scores are usually this |
| CVSS-BT | Base + Threat | You know the exploit maturity |
| CVSS-BE | Base + Environmental | You know the client's environment |
| **CVSS-BTE** | Base + Threat + Environmental | **Default for this skill's reports** |

- **Threat (E):** set `E:A` (Attacked) if the CVE is in CISA KEV or exploitation is otherwise
  evidenced; `E:P` if a public proof-of-concept exists; `E:U` if neither.
- **Environmental:** set CR/IR/AR (confidentiality, integrity, availability requirements) from
  data sensitivity. Use modified base metrics for exposure (e.g. `MAV:A` if only reachable
  inside a VPN) and for compensating controls.
- Compute the score with the FIRST calculator (first.org/cvss/calculator/4.0); do not hand-compute or copy a score from a third-party calculator. Vectors that differ in one metric can share a MacroVector yet score differently (e.g. `…/VA:H/…` vs `…/VA:N/…`), so never reuse a score across vectors.
- Always publish score **and** vector (FIRST condition of use), in this form:
  `CVSS-BTE <score from calculator> — CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:A/CR:H`.
- Add a pre-filled verification link so a reviewer can reproduce the score in one click. Use NVD's v4.0
  calculator, which NVD states is based on FIRST's and accepts the vector in the URL:
  `https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator?vector=<metrics after "CVSS:4.0/", URL-encoded>&version=4.0`.
  `scripts/vuln_intel.py --json` emits this as `calculator_url`. If the linked score differs from your
  FIRST-calculator score, the vector was mistyped: fix it before the report ships.
- Bands: **None 0.0 · Low 0.1–3.9 · Medium 4.0–6.9 · High 7.0–8.9 · Critical 9.0–10.0**.
- AI/agentic findings: add AIVSS v0.8 as a separately labelled, pre-standard figure (see module-ai-agent.md).

## 2. Priority — CISA SSVC (deployer tree)

| Decision point | Values | Source of truth |
|----------------|--------|-----------------|
| Exploitation | None / Public PoC / Active | KEV, vendor advisory, threat intel; NVD CISA-ADP SSVC data where present |
| Automatable | No / Yes | Can steps 1–4 of the kill chain be automated reliably? |
| Technical Impact | Partial / Total | Total = full control of the affected component |
| Mission & Well-being | Low / Medium / High | Client's business context |

Outcomes (CISA wording):

| Outcome | Meaning | Default response |
|---------|---------|------------------|
| **Track** | No action needed now | Remediate within the standard cycle |
| **Track\*** | Monitor for change | Standard cycle; re-check exploitation status |
| **Attend** | Needs attention from leadership | Remediate sooner than the standard cycle |
| **Act** | Needs immediate leadership attention | Remediate or mitigate as soon as possible |

These decision points line up with BOD 26-04's four criteria (Exploitation ↔ KEV Status, Automatable ↔ Exploit Automation, Technical Impact ↔ Post-Exploitation Technical Impact, plus Asset Exposure), so an SSVC decision can be mapped directly to a BOD 26-04 timeline.

Rules:
- **KEV-listed findings are never below Attend.**
- **Act + KEV + publicly exposed**: recommend a compromise check (forensic triage) alongside the fix, as BOD 26-04 requires of US agencies.
- **EPSS v4** (probability + percentile, with model version and score date) orders items
  *within* one SSVC outcome. It is not a band modifier.
- Where NVD carries CISA-ADP SSVC values, cite them; otherwise state your own decision-point
  values so the reviewer can reproduce the outcome.

## 3. Confidence

| Level | Meaning | Required evidence |
|-------|---------|-------------------|
| **Confirmed** | Exploitable as described | Benign proof executed within scope, or a configuration/flag that is itself the flaw |
| **Likely** | Flaw visible in code/config but not safely exercisable here | Code path + reasoning; state what proof would need |
| **Informational** | Hardening gap or best-practice deviation | Observation |

Report Confirmed and Likely separately; never present Likely as proven.

## 4. Remediation timelines — what an authority actually sets

SLAs are **contractual**. Cite the authority only for the numbers it publishes; label the rest
"organisation-defined".

| Source | Applies to | Timeline it sets |
|--------|------------|------------------|
| CISA **BOD 26-04** *Prioritizing Security Updates Based on Risk* (10 Jun 2026; supersedes and revokes BOD 19-02 and BOD 22-01) | US federal civilian (FCEB) agencies; a benchmark for everyone else | Timeline set per vulnerability from four criteria: Asset Exposure, KEV Status, Exploit Automation, Post-Exploitation Technical Impact. The KEV `dueDate` reflects them. Highest risk (e.g. publicly exposed + total impact + automatable) → **3 days plus forensic triage** for compromise; lower risk → longer timelines, possibly deferred to the next system upgrade |
| **PCI DSS v4.0.1** Req. 6.3.3 | Cardholder-data environment | Critical security patches within **one month** of release; others per risk ranking (6.3.1) |
| **CIS Controls v8.1** Safeguard 7.7 | Any adopter | Remediation cycle **monthly or more often** |
| FedRAMP | US federal cloud services | Use the current FedRAMP continuous-monitoring standard |
| NCSC-NL / BSI | — | No numeric SLA published |

**Organisation-defined default** (a common industry convention; use only if the client
has none): Act → 24–72 h · Attend → 14 days · Track\* → 30–60 days · Track → 90 days or next
maintenance cycle. Always override with the KEV `dueDate` (BOD 26-04) or PCI 6.3.3 where those apply.

Do not cite BOD 22-01 or BOD 19-02 as current: both were revoked on 10 Jun 2026.

## 5. Noise control

- De-duplicate by root cause (one "missing security headers" finding listing all origins, not twenty).
- Drop version-string-only matches when the vulnerable function is provably unused; record them in an appendix as "not applicable, verified".
- Keep a short "out of scope / not tested" list so absence of a finding is not read as a pass.

## 6. Re-test plan

For each Act/Attend item, state what to re-run after the fix, the expected result, and the
regression risk of the fix itself (e.g. stricter CORS breaking a legitimate partner origin).

## 7. Context figures (cite exactly)

- Time-to-exploit: Google Mandiant/GTIG mean time-to-exploit was 5 days for 2023 (an
  outlier-adjusted **mean**, not a median), −1 day for 2024, and an estimated −7 days for 2025
  (M-Trends 2026): on average, exploitation now precedes patch availability.
- Verizon 2025 DBIR: exploitation of vulnerabilities was the initial vector in 20% of breaches;
  edge-device/VPN exploitation was 22% of vulnerability-exploitation incidents (up from 3%);
  organisations fully remediated 54% of the featured edge-device vulnerabilities, median 32 days.
- Verizon 2026 DBIR, as cited by CISA ("Patch Smarter, Not Harder", 2026): only 26% of KEV-listed
  vulnerabilities were fully remediated in 2025 (38% the year before); median time to full
  resolution 43 days.
