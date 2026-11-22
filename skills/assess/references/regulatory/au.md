# Australia (federal)

Checked 2026-11-19. Primary sources: legislation.gov.au, cyber.gov.au, oaic.gov.au,
cisc.gov.au, apra.gov.au.

| Instrument | Applies to (role) | What a finding can trigger | Deadline | Authority / channel | Tier · status |
|------------|-------------------|----------------------------|----------|---------------------|---------------|
| **Privacy Act 1988** Part IIIC — Notifiable Data Breaches scheme | APP entities (`controller`) | Eligible data breach likely to result in **serious harm** | Assess a suspected breach reasonably and expeditiously, **≤30 days** (s 26WH); notify OAIC and individuals as soon as practicable (s 26WK–26WL) | OAIC | `may_trigger_now` |
| **Security of Critical Infrastructure Act 2018** Part 2B | `au_soci_responsible` | Cyber security incident with **significant impact** on asset availability / with **relevant impact** | Significant: **12 h** (oral report → written record within 84 h). Relevant: **72 h** (oral → written within 48 h) | ASD's ACSC (cyber.gov.au) | `may_trigger_now` |
| **Cyber Security Act 2024** Part 3 + Ransomware Payment Reporting Rules 2025 | `au_reporting_business` (turnover > AUD 3 m) or SOCI responsible entity | Ransomware / cyber-extortion **payment** made by or for the entity | **72 h** after payment or becoming aware of it | ASD (cyber.gov.au) | `may_trigger_now` since 30 May 2025 |
| **Cyber Security Act 2024** Part 2 + Smart Devices Rules | Consumer smart-device `manufacturer` / supplier | No universal default passwords; vulnerability-reporting channel; declared support period; statement of compliance | — | Department of Home Affairs (enforcement) | In force since **4 Mar 2026** (conformity, no reporting clock) |
| **APRA CPS 234 Information Security** | `au_apra_regulated` | Material information-security incident; material control weakness | Incident: as soon as possible, **≤72 h**; control weakness: ≤10 business days | APRA | `may_trigger_now` |

## Testing law and disclosure

- Criminal Code Act 1995 Part 10.7: `testing-law.md`.
- ASD's ACSC vulnerability reporting (cyber.gov.au).
