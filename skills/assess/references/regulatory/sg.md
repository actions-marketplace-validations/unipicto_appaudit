# Singapore

Checked 2026-11-20. Primary sources: sso.agc.gov.sg (Singapore Statutes Online), csa.gov.sg,
pdpc.gov.sg, mas.gov.sg. Quote the statute or notice text in contractual documents.

| Instrument | Applies to (role) | What a finding can trigger | Deadline | Authority / channel | Tier · status |
|------------|-------------------|----------------------------|----------|---------------------|---------------|
| **PDPA 2012** Part 6A (ss. 26A–26E) + Personal Data Protection (Notification of Data Breaches) Regulations 2021 | `controller` (organisation); a data intermediary must notify the organisation without undue delay | Data breach that causes or is likely to cause **significant harm**, or affects **≥500 individuals** | Assess whether notifiable **within 30 days** of becoming aware (PDPC position); notify PDPC as soon as practicable and **≤3 calendar days after determining** it is notifiable; affected individuals as soon as practicable (significant harm) | PDPC (online form) | `may_trigger_now` |
| **Cybersecurity Act 2018** s. 14 + Cybersecurity (Provider-Owned Critical Information Infrastructure) Regulations 2018 (amended 2025) | `sg_cii_owner` (designated provider-owned CII owner; also designated providers of third-party-owned CII, s. 16I) | Prescribed cybersecurity incident in respect of the CII or an interconnected system under the owner's control | Notify the Commissioner **within 2 hours** of becoming aware (by phone); supplementary details **within 72 hours**; final report **within 30 days** after the supplementary details (per CSA forms page) | Cyber Security Agency (CSA) | `may_trigger_now`; the 2024 amendments for CII and systems of temporary cybersecurity concern apply since **31 Oct 2025** |
| **Cybersecurity (Amendment) Act 2024** Parts 3C and 3D | Entities of special cybersecurity interest; major foundational digital infrastructure (FDI) service providers (cloud, data centres) | Prescribed incidents disrupting the FDI service in Singapore | To be prescribed | CSA | `readiness` — Parts 3C and 3D **not yet commenced** |
| **MAS Notices on Technology Risk Management** (FSM-N01 to N25 series, issued 9 May 2024) | `sg_mas_fi` (banks, insurers, payment and other MAS-licensed financial institutions) | "Relevant incident": system malfunction or IT security incident with severe and widespread impact or material customer impact | Notify MAS **≤1 hour** after discovery; root-cause and impact report **≤14 days** | MAS (initial notification; incident template on MAS-Tx from 1 Feb 2026) | `may_trigger_now` |
| **MAS TRM Notice amendments** (consultation 10 Jun 2026, closed 31 Jul 2026) | `sg_mas_fi` | Gaps against proposed controls (asset inventory, immutable/offline backup, monitoring, incident management) | — | MAS | `readiness` — proposals, not in force |
| **Cybersecurity Labelling Scheme (CLS)** | Consumer IoT `manufacturer` (voluntary) | Gaps against CLS level criteria (Level 1 ≈ ETSI EN 303 645 baseline) | — | CSA | Voluntary; mutual recognition with Japan JC-STAR since 1 Jun 2026 |

## Testing law and disclosure

- Computer Misuse Act 1993: `testing-law.md`. Written authorization is the basis for lawful testing.
- Vulnerability reports: the vendor's channel first; SingCERT (CSA) for coordination.
- Dual reporting: a CII owner that is also an MAS-regulated FI can face the 1-hour MAS clock and
  the 2-hour CSA clock for one event, plus PDPC if personal data is affected.
