# India

Checked 2026-11-20. Primary sources: cert-in.org.in, meity.gov.in, egazette.gov.in, rbi.org.in,
sebi.gov.in, irdai.gov.in. Quote the direction, rule or circular in contractual documents.

| Instrument | Applies to (role) | What a finding can trigger | Deadline | Authority / channel | Tier · status |
|------------|-------------------|----------------------------|----------|---------------------|---------------|
| **CERT-In Directions** of 28 Apr 2022 under IT Act 2000 s. 70B(6) (+ FAQs, May 2022) | `in_cert_in_covered`: service providers, intermediaries, data centres, body corporates and government organisations with ICT systems in India | Any cyber incident type in Annexure I (incl. data breach, data leak, ransomware, unauthorized access, compromise of critical systems, attacks on applications, IoT, AI/ML systems) | Report **within 6 hours** of noticing or being notified; keep ICT logs for a rolling **180 days** (in India, or retrievable on request); synchronise clocks to NIC/NPL NTP | CERT-In (incident e-mail or portal listed on cert-in.org.in) | `may_trigger_now` since **27 Jun 2022** |
| **DPDP Act 2023** s. 8(6) + **DPDP Rules 2025** Rule 7 (G.S.R. 846(E), 13 Nov 2025) | `controller` (data fiduciary); processors through the fiduciary | Personal data breach | Intimate each affected data principal **without delay**; intimate the Data Protection Board **without delay**, then a detailed update **within 72 hours** (or an extension the Board allows) | Data Protection Board of India | `readiness` — Rule 7 applies from **13 May 2027** (18 months after notification); Board established 13 Nov 2025; consent managers from 13 Nov 2026 |
| **RBI** cyber security frameworks and Master Direction on IT Governance, Risk, Controls and Assurance Practices (2023) | `in_rbi_regulated` (banks, NBFCs, payment system operators) | Cyber security incident | Report to RBI within **2–6 hours** of detection (per the applicable direction); root-cause follow-up | RBI (CSITE / incident reporting portal) | `may_trigger_now` |
| **SEBI Cybersecurity and Cyber Resilience Framework (CSCRF)** (circular of 20 Aug 2024, as amended) | `in_sebi_regulated` (brokers, depositories, AMCs, market infrastructure institutions) | Cyber attack, incident or breach | Notify SEBI **within 6 hours** of detection (email), then the incident portal **within 24 hours**; CERT-In separately within 6 hours | SEBI (and CERT-In) | `may_trigger_now` |
| **IRDAI Information and Cyber Security Guidelines 2023** | Insurers and insurance intermediaries | Cyber incident | As per the guidelines (6 hours to CERT-In applies in parallel) | IRDAI | `may_trigger_now` (confirm the IRDAI timeline in the current guidelines) |

## Testing law and disclosure

- Information Technology Act 2000 ss. 43 (unauthorized access, civil liability) and 66 (offence):
  `testing-law.md`. Written authorization is the basis for lawful testing.
- Vulnerability reports: the vendor's channel first; CERT-In accepts vulnerability reports under
  its Responsible Vulnerability Disclosure and Coordination policy.
- One breach at a regulated entity can start several clocks: CERT-In 6 h, the sector regulator
  (RBI 2–6 h, SEBI 6 h) and, from May 2027, the Data Protection Board (72 h). The shortest
  clock governs internal escalation.
