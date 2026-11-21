# United States — federal and New York

Checked 2026-11-19. Primary sources: sec.gov, cisa.gov, hhs.gov, ftc.gov, acquisition.gov
(DFARS), dfs.ny.gov, nysenate.gov (GBL § 899-aa), fcc.gov. Other US states have their own
breach-notification laws: **not covered** in this version beyond New York — list them as "not
assessed" when residents of other states are affected.

## Federal

| Instrument | Applies to (role) | What a finding can trigger | Deadline | Authority / channel | Tier · status |
|------------|-------------------|----------------------------|----------|---------------------|---------------|
| **SEC Form 8-K Item 1.05** (Release 33-11216) + Reg. S-K Item 106 | `listed_us` | Cybersecurity incident the registrant determines to be **material** | 8-K within **4 business days after the materiality determination** (determination itself "without unreasonable delay"); amend when new material information emerges | SEC (EDGAR) | `may_trigger_now` |
| **FTC Safeguards Rule** — 16 CFR 314.4(j) | `ftc_financial` (non-bank financial institutions) | Unauthorized acquisition of **unencrypted customer information of ≥500 consumers** | As soon as possible, **no later than 30 days after discovery** | FTC online form | `may_trigger_now` since 13 May 2024 |
| **DFARS 252.204-7012** | `us_dod_contractor` (covered defense information / CUI) | Cyber incident affecting a covered contractor information system or covered defense information | **72 h from discovery**; preserve images 90 days | DoD via DIBNet (medium-assurance certificate) | `may_trigger_now`. CMMC Phase 2 was **suspended on 13 Jul 2026**; DFARS 7012 and NIST SP 800-171 duties are unchanged |
| **HIPAA Breach Notification Rule** — 45 CFR 164.400–414 | `hipaa_covered` (`hipaa_ba` → notify covered entity) | Breach of unsecured PHI | Individuals without unreasonable delay, ≤60 days from discovery; HHS ≤60 days if ≥500 individuals (else annual log) | HHS OCR | `may_trigger_now` |
| **HIPAA Security Rule amendments** (NPRM 6 Jan 2025, RIN 0945-AA22) | `hipaa_covered`, `hipaa_ba` | Gaps against proposed mandatory controls (MFA, encryption, asset inventory, scans, pentests) | — | HHS OCR | `readiness` — moved to HHS long-term agenda (target July 2027); the existing Security Rule applies |
| **CIRCIA** (6 U.S.C. 681 et seq.) | `ci_us` (definition set by the final rule) | Covered cyber incident; ransom payment | 72 h after reasonable belief; 24 h after a ransom payment | CISA | `readiness` — final rule sent to OMB review 1 Oct 2026; not in force |
| **FDA § 524B FD&C Act** (cyber devices) | Medical-device `manufacturer` | Premarket cybersecurity documentation gaps (SBOM, vulnerability plan) | — | FDA (premarket submission) | In force; conformity issue, no reporting clock |
| **US Cyber Trust Mark** (FCC, 47 CFR Part 8) | Consumer IoT `manufacturer` (voluntary) | Gaps against label criteria | — | FCC / ioXt (lead administrator) | Voluntary; implementation rules still out for comment (Oct 2026) |

## New York

| Instrument | Applies to (role) | What a finding can trigger | Deadline | Authority / channel | Tier · status |
|------------|-------------------|----------------------------|----------|---------------------|---------------|
| **23 NYCRR 500.17** (NY DFS Cybersecurity Regulation, 2nd amendment) | `ny_dfs_covered` | Cybersecurity incident at the entity, an affiliate or a third-party service provider; extortion payment | Incident: as promptly as possible, **≤72 h after determining** it occurred. Extortion payment: notice **≤24 h**, written justification **≤30 days** | NY DFS portal | `may_trigger_now` |
| **NY GBL § 899-aa** (SHIELD Act, amended Dec 2024) | Any business owning/licensing NY residents' private information (`data_subject_regions` includes `US-NY`) | Breach of private information | Residents: most expedient time, **≤30 days after discovery**; AG, Dept. of State, State Police (and NY DFS for DFS-regulated entities). Service providers → data owner within 30 days | NY AG and others | `may_trigger_now` |

## Notes for counsel

- One event can start several US clocks: NY DFS 72 h usually runs first; the SEC clock starts
  only at the materiality determination; FTC 30 days and GBL 30 days run from discovery.
- FTC Safeguards notifications are published by the FTC.
