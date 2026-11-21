# Regulatory module — index and selection procedure

**Purpose.** Flag the legal obligations a finding *may* trigger, for the client and their counsel
to decide. This module never states that a notification is required, never decides materiality
or awareness, and is not legal advice. Quote the official text (Official Journal, Federal
Register, legislation.gov.uk, Justice Laws, Federal Register of Legislation, Staatsblad) in
contractual documents.

Regulatory data checked: **2026-11-20** (EU and NL entries: 2026-11-18; US, UK, CA, AU: 2026-11-19). Each file states its own
check date. Refresh quarterly; `check_update.py` warns when this data is older than 90 days.

---

## 1. Coverage in this version

| Wave | Jurisdiction | File | Coverage |
|------|--------------|------|----------|
| 1 | European Union | `eu.md` | Full: triggers, deadlines, readiness |
| 1 | Netherlands | `nl.md` | Full (national layer on top of `eu.md`) |
| 1 | United States — federal + New York | `us.md` | Full |
| 1 | United Kingdom | `uk.md` | Full |
| 1 | Canada | `ca.md` | Full (federal) |
| 1 | Australia | `au.md` | Full (federal) |
| — | China | `testing-law.md`, `disclosure.md` | **Warnings only**: testing law and vulnerability-disclosure duties; no trigger flags |
| 2 | Singapore | `sg.md` | Full |
| 2 | Japan | `jp.md` | Full |
| 2 | India | `in.md` | Full (CERT-In, DPDP readiness, RBI/SEBI/IRDAI) |
| — | Any other jurisdiction | — | Not covered. Report as "not assessed" |

Always read `testing-law.md` before active testing and `disclosure.md` before recommending
disclosure.

## 2. Jurisdiction profile (from `scope.json` → `jurisdiction_profile`)

| Field | Meaning | Example |
|-------|---------|---------|
| `established_in` | Where the client is incorporated / has its main establishment | `["NL"]` |
| `markets` | Where the product or service is placed on the market / offered | `["EU", "US", "UK"]` |
| `sector` | Sector(s) | `["finance", "energy", "health", "telecom", "defence", "consumer-iot"]` |
| `roles` | Regulatory roles the client holds (vocabulary in §3) | `["manufacturer", "controller", "ny_dfs_covered"]` |
| `data_subject_regions` | Where affected people live | `["EU", "US-NY", "CA"]` |
| `hosting_locations` | Where in-scope systems physically run (incl. cloud regions) | `["EU", "US"]` |
| `tester_location` | Where the assessor operates from | `["NL"]` |
| `evidence_storage_location` | Where evidence will be stored | `"NL"` |
| `counsel_confirmed` | Jurisdictions where the client's counsel confirmed testing may proceed | `["CN"]` |

Use ISO 3166-1 alpha-2 codes; `EU` for the Union as a whole; `US-NY` for New York.
If the profile is missing or empty, **do not guess**: flag nothing, and state in the report that
regulatory triggers were not assessed because no jurisdiction profile was given.

## 3. Selection procedure

1. Build the set J = `established_in` ∪ `markets` ∪ `data_subject_regions` ∪ `hosting_locations`.
2. Map codes to files: any EU member state or `EU` → `eu.md` (plus `nl.md` for `NL`);
   `US`, `US-*` → `us.md`; `GB`/`UK` → `uk.md`; `CA` → `ca.md`; `AU` → `au.md`;
   `SG` → `sg.md`; `JP` → `jp.md`; `IN` → `in.md`.
   `CN` → warnings in `testing-law.md` and `disclosure.md` only.
   Everything else → list under "Jurisdictions not assessed".
3. In each selected file, an entry applies only when the client's `roles` and `sector` match the
   entry's "Applies to" column. When the profile does not say, do not assume the role: list the
   entry under "Possibly applicable — role not confirmed" for counsel.
4. For each finding, test the entry's trigger against the facts of the finding (exploitation
   evidence, personal data reached, service impact, ransom payment). Record the facts used.

### Role vocabulary

| Role | Meaning |
|------|---------|
| `manufacturer` | Places products with digital elements on a market (CRA, RED, AU smart-device standard, UK PSTI; voluntary labels: US Cyber Trust Mark, SG CLS, JP JC-STAR) |
| `controller` / `processor` | Personal-data roles (GDPR, UK GDPR, PIPEDA, AU Privacy Act, SG PDPA, JP APPI, IN DPDP) |
| `essential_entity` / `important_entity` | NIS2 / Cbw entity classes |
| `financial_entity_eu` | DORA scope |
| `listed_us` | SEC registrant |
| `ci_us` | US critical-infrastructure entity (CIRCIA readiness) |
| `ny_dfs_covered` | Licensed/regulated by NY DFS (23 NYCRR 500) |
| `ftc_financial` | Non-bank financial institution under the FTC Safeguards Rule |
| `hipaa_covered` / `hipaa_ba` | HIPAA covered entity / business associate |
| `us_dod_contractor` | Holds covered defense information (DFARS 252.204-7012) |
| `uk_oes` / `uk_rdsp` | UK NIS operator of essential service / relevant digital service provider |
| `ca_frfi` | Federally regulated financial institution (OSFI) |
| `ca_designated_operator` | Designated operator under the Critical Cyber Systems Protection Act |
| `au_soci_responsible` | Responsible entity for a SOCI critical-infrastructure asset |
| `au_apra_regulated` | APRA-regulated entity (CPS 234) |
| `au_reporting_business` | Carries on business in Australia with turnover > AUD 3 m (ransomware payment reporting) |
| `sg_cii_owner` | Owner of designated critical information infrastructure in Singapore (incl. third-party-owned CII providers) |
| `sg_mas_fi` | Financial institution under the MAS Technology Risk Management Notices |
| `jp_special_infra_operator` | Designated special social infrastructure operator under Japan's Act No. 42 of 2025 |
| `in_cert_in_covered` | Service provider, intermediary, data centre, body corporate or government body with ICT systems in India (CERT-In Directions) |
| `in_rbi_regulated` / `in_sebi_regulated` | Entity regulated by RBI / SEBI (CSCRF) |

## 4. Two tiers — never mix them

| Tier | When | How it appears in outputs |
|------|------|---------------------------|
| `may_trigger_now` | Instrument is in force for this role **and** the finding's facts plausibly meet the trigger | "Deadlines that may be running", with the deadline and authority |
| `readiness` | Instrument adopted but not yet applying, still a bill, or role not confirmed | "Prepare for", with the expected date and status |

## 5. How to record a flag (findings.json → `regulatory[]`)

```json
{ "jurisdiction": "EU", "instrument": "Cyber Resilience Act", "provision": "Art. 14",
  "tier": "may_trigger_now",
  "basis": "client is manufacturer; product on EU market; vulnerability KEV-listed (actively exploited)",
  "deadline": "early warning 24 h, notification 72 h, final report 14 days after a fix is available",
  "clock_start": "when the manufacturer becomes aware of the actively exploited vulnerability",
  "authority": "ENISA single reporting platform", "decided_by": "client/counsel",
  "source": "eur-lex.europa.eu/eli/reg/2024/2847/oj", "source_checked": "2026-11-18" }
```

Rules:
- State the facts that make the trigger plausible; never write that notification **is** required.
- If the deadline may already be running (exploitation observed in the client's environment), say
  so in the brief's first section, not only in the finding.
- Where two regimes apply to one event, list both and note when the earlier deadline governs
  internal escalation (e.g. NY DFS 72 h vs SEC 4 business days).
- List "Jurisdictions not assessed" in every brief and report.
