# Standards, Editions & Refresh Procedure

**Verified 2026-11-18 against the issuing bodies** (owasp.org, genai.owasp.org, mas.owasp.org,
aivss.owasp.org, first.org, cisa.gov, nvd.nist.gov, csrc.nist.gov, cwe.mitre.org,
cisecurity.org, etsi.org, pcisecuritystandards.org, eur-lex.europa.eu,
digital-strategy.ec.europa.eu, officielebekendmakingen.nl, ncsc.nl, agentskills.io).
Standards revise; when outbound HTTP is available, spot-check the "Current edition" column
before citing in a report. Items in **§3 Open checks** were not confirmed from a primary source.

## 1. Editions

### Web, API, mobile
| Standard | Current edition (verified) | Authority |
|----------|----------------------------|-----------|
| OWASP Top 10 | **2025, final** — OWASP states it is "the most current released version" (owasp.org/projects/top-ten) and the repository README marks it "RELEASED … (Final)", 2021 "SUPERSEDED". **OWASP publishes no official publication date**: cite it as "OWASP Top 10:2025 (final)" with the access date. Release candidate presented for OWASP Global AppSec USA, Washington DC (GitHub milestone *2025-release* due 6 Nov 2025). Do not cite the 24 Dec 2025 date: it appears only in secondary sources. Categories: A01 Broken Access Control (incl. SSRF) · A02 Security Misconfiguration · A03 Software Supply Chain Failures · A04 Cryptographic Failures · A05 Injection · A06 Insecure Design · A07 Authentication Failures · A08 Software or Data Integrity Failures · A09 Security Logging and Alerting Failures · A10 Mishandling of Exceptional Conditions | owasp.org/Top10/2025 |
| OWASP ASVS | **5.0.0** (30 May 2025); IDs `v5.0.0-x.y.z` | owasp.org/www-project-application-security-verification-standard |
| OWASP API Security Top 10 | **2023** (latest as of 18 Nov 2026) | owasp.org/API-Security |
| OWASP MASVS | **v2.1.0** (18 Jan 2024): 8 groups / 24 controls — STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, CODE, RESILIENCE, PRIVACY | github.com/OWASP/masvs/releases |
| OWASP MASTG | **v2.0.0** (Jun 2026) | github.com/OWASP/mastg/releases |
| OWASP MASWE | **v1.0.0** — 78 weaknesses, MASWE-0001–0078 | mas.owasp.org/news |
| NIST SP 800-63B | **-4** (final Aug 2025) | pages.nist.gov/800-63-4 |
| NIST SP 800-52 | Rev. 2 (TLS) | csrc.nist.gov |
| RFC 8725 | JWT BCP (BCP 225) | rfc-editor.org |

### IoT, hardware, firmware
| Standard | Current edition (verified) | Authority |
|----------|----------------------------|-----------|
| OWASP ISVS | **1.0** — release notes: "Official Release - October 2025" (the project site also shows a "1.0.0-RC2" banner). Chapters V1 IoT Ecosystem · V2 User Space Application · V3 Software Platform · V4 Communication · V5 Hardware Platform; includes 7 new L3 post-quantum requirements. **OWASP's own requirement counts are inconsistent** (site: 156; release notes: 165 headline, per-chapter 40/34/49/46/13 = 182): cite requirement IDs, never a total | owasp.org/IoT-Security-Verification-Standard-ISVS · github.com/OWASP/IoT-Security-Verification-Standard-ISVS/blob/master/RELEASE_NOTES.md |
| OWASP IoT Top 10 | 2018 (latest) | owasp.org/www-project-internet-of-things |
| ETSI TS 103 701 | **V2.1.1 (2025-05)** — Conformance Assessment of Baseline Requirements; references EN 303 645 V3.1.3 (supersedes V1.1.1, 2021) | etsi.org/deliver/etsi_ts/103700_103799/103701/02.01.01_60/ |
| ETSI EN 303 645 | **V3.1.3 (2024-09)** — §5.1 No universal default passwords · 5.2 Manage vulnerability reports · 5.3 Keep software updated · 5.4 Securely store sensitive security parameters · 5.5 Communicate securely · 5.6 Minimize exposed attack surfaces · 5.7 Ensure software integrity · 5.8 Ensure personal data is secure · 5.9 Resilience to outages · 5.10 Examine system telemetry data · 5.11 Easy deletion of user data · 5.12 Easy installation and maintenance · 5.13 Validate input data · 6 Data protection provisions | etsi.org |
| NIST IR 8259 | **Rev. 1** (final 20 Apr 2026); 8259A (May 2020) and 8259B (Aug 2021) unchanged | csrc.nist.gov/pubs/ir/8259/r1/final |
| NIST SP 800-213 | 2021 final; Rev. 1 draft (24 Jun 2026) | csrc.nist.gov |
| NIST SP 800-193 / 800-147 | Platform firmware resiliency / BIOS protection | csrc.nist.gov |
| RED Delegated Reg. (EU) 2022/30 + EN 18031-1/-2/-3:2024 | Mandatory since **1 Aug 2025** | eur-lex.europa.eu |
| EUCC | Impl. Reg. (EU) 2024/482, applicable 27 Feb 2025 | eur-lex.europa.eu |
| SESIP / PSA Certified / IEC 62443-4-2 | EN 17927 / current / current | cen.eu · psacertified.org · iec.ch |

### AI and agentic
| Standard | Current edition (verified) | Authority |
|----------|----------------------------|-----------|
| OWASP Top 10 for LLM Applications | **2026** (published 4 Aug 2026; announced 1 Sep 2026) — LLM01 Prompt Injection · LLM02 Sensitive Information Disclosure · LLM03 Excessive Agency · LLM04 Supply Chain · LLM05 Data and Model Poisoning · LLM06 Unbounded Consumption · LLM07 Misinformation · LLM08 Hidden Context Exposure · LLM09 Vector and Embedding Weaknesses · LLM10 Improper Output Handling | github.com/GenAI-Security-Project/GenAI-LLM-Top10 · genai.owasp.org |
| OWASP Top 10 for Agentic Applications | **2026** (Dec 2025) — ASI01–ASI10 (see module-ai-agent.md) | genai.owasp.org |
| OWASP Agentic Skills Top 10 | **Incubator** (OWASP badge). Titles AST01–AST10 confirmed on OWASP pages; repo labels it "1.0 (2026 Edition)" with the v1.0 release and flagship submission scheduled for Q4 2026; licence CC BY-SA 4.0. OWASP publishes no release date: cite undated with the access date (do not cite the 17 Aug 2026 date, which appears only in secondary sources) | owasp.org/www-project-agentic-skills-top-10 · github.com/OWASP/www-project-agentic-skills-top-10 |
| OWASP AIVSS | **v0.8** (19 Mar 2026), pre-standard | aivss.owasp.org |
| OWASP Agent Control Standard | v0.x (1 Sep 2026), emerging | genai.owasp.org/resource/agent-control-standard-acs |
| NIST AI 100-1 / AI 600-1 / AI 100-2 E2025 / SP 800-218A | AI RMF / GenAI profile / adversarial ML taxonomy / SSDF AI profile | nist.gov · csrc.nist.gov |
| ISO/IEC 42001 | 2023 | iso.org |
| EU AI Act | Reg. (EU) 2024/1689, amended by Reg. (EU) 2026/1744 (Digital Omnibus; adopted 8 Jul 2026, in force 27 Jul 2026 per EUR-Lex) | eur-lex.europa.eu/eli/reg/2026/1744/oj |

### Scoring, intelligence, weakness data
| Standard | Current edition (verified) | Authority |
|----------|----------------------------|-----------|
| CVSS | **v4.0** (Nov 2023); Consumer Implementation Guide v1.01 (Jan 2026); no v4.1/v5. Score with the FIRST calculator; pre-filled verification links use NVD's v4.0 calculator (based on FIRST's; `?vector=…&version=4.0`) | first.org/cvss · nvd.nist.gov/vuln-metrics/cvss/v4-calculator |
| EPSS | **Model v4** (17 Mar 2025); daily scores | first.org/epss |
| CISA KEV | Daily feed; read `count` at runtime. Catalogue criteria carried forward from BOD 22-01 into **BOD 26-04** | cisa.gov/known-exploited-vulnerabilities-catalog |
| CISA SSVC | Deployer tree; NVD carries CISA-ADP SSVC (schema v2.0.3) since 17 Jun 2026 | cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc |
| ENISA EUVD | Launched May 2025 (NIS2 Art. 12(2)) | euvd.enisa.europa.eu |
| CWE Top 25 | **2025** (Dec 2025; #1 CWE-79) + companion **2025 CWE Top 10 KEV Weaknesses** (same scoring method applied to the KEV subset; led by CWE-78 OS Command Injection, CWE-416 Use After Free, CWE-787 Out-of-bounds Write, CWE-306 Missing Authentication for Critical Function) | cwe.mitre.org/top25 · cwe.mitre.org/top25/archive/2025/2025_kev_list.html |

### Process, governance, compliance
| Standard | Current edition (verified) | Authority |
|----------|----------------------------|-----------|
| CISA BOD 26-04 | *Prioritizing Security Updates Based on Risk*, issued 10 Jun 2026; supersedes and revokes BOD 19-02 and BOD 22-01; binds US FCEB agencies; implementation guidance includes forensic-triage steps | cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk |
| NIST SP 800-115 | Sep 2008 (final, still current) | csrc.nist.gov/pubs/sp/800/115/final |
| NIST SP 800-53 | Rev. 5 Release 5.2.0 (Aug 2025) — RA-5 | csrc.nist.gov |
| NIST SSDF SP 800-218 | v1.1 (Feb 2022) final; v1.2 draft (Dec 2025) | csrc.nist.gov/projects/ssdf |
| NIST IR 8547 | **Final 27 Oct 2026**, *Transition to Post-Quantum Cryptography Standards*. Quantum-vulnerable signatures (ECDSA, EdDSA, RSA) and key establishment (FF/EC DH, MQV, RSA) are **deprecated after 2030, disallowed after 2035** (§4.1.1–4.1.2); 112-bit symmetric disallowed in 2030 (§4.1.3); **ML-KEM-768 is the default** parameter set; hybrid key establishment and dual signatures accommodated in FIPS 140 when combined with a NIST-approved scheme (§3.2). US agency targets (EO 14412 / OMB M-26-15): PQC key establishment by 31 Dec 2030, signatures by 31 Dec 2031 | csrc.nist.gov/pubs/ir/8547/final · nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8547.pdf |
| FIPS 203 / 204 / 205 | ML-KEM / ML-DSA / SLH-DSA (Aug 2024) | csrc.nist.gov |
| OWASP Cheat Sheet Series | Living documents (cite title + access date). Used by the web and API modules: Input Validation · Mass Assignment · Query Parameterization · NoSQL Security · Database Security · Secrets Management · Third Party Payment Gateway Integration · Transaction Authorization · NPM Security · Nodejs Security · Password Storage · HTTP Headers. Titles confirmed 2026-11-19 | cheatsheetseries.owasp.org |
| CIS Controls | **v8.1** — 7.5 internal scans quarterly+ · 7.6 external scans monthly+ · 7.7 remediate monthly+ | cisecurity.org |
| PCI DSS | **v4.0.1** only active version — 11.3.1/11.3.2 quarterly scans · 11.4 annual pentest · 6.3.3 critical patches ≤1 month · 6.4.3 payment-page script inventory and authorization · 11.6.1 payment-page change and tamper detection | pcisecuritystandards.org |
| Regulatory obligations (EU, NL, US federal + NY, UK, CA, AU, SG, JP, IN; China warnings) | See regulatory/index.md and the per-jurisdiction files (checked 2026-11-18 to 2026-11-20) | per file |
| NCSC-NL ICT-beveiligingsrichtlijnen voor webapplicaties | **Updated edition** (PDF "07-24_0", posted 17-4-2026; page gives no publication date): texts rewritten, structure unchanged, guidelines tightened (U/TV.01, U/WA.03–05, U/PW.02/03/07, U/NW.03/04), OpenCRE mappings to ISO 27002 / NIST SP 800-53 Rev. 5. Sits under the *Beleids- en beheersingsrichtlijnen voor de ontwikkeling van veilige software*, which also covers the mobile-app guidelines | ncsc.nl/webapplicaties/ict-beveiligingsrichtlijnen-webapplicaties |
| NCSC-NL TLS v2.1 / Leidraad CVD | Current per ncsc.nl | ncsc.nl |
| BSI TR-02102-1/-2 | Current-year edition | bsi.bund.de |
| Agent Skills specification | `name` (1–64, lowercase/digits/hyphen, = folder) + `description` (1–1024) required; optional `license`, `compatibility`, `metadata`, `allowed-tools` | agentskills.io/specification |

### Output formats (used by `scripts/build_outputs.py` and on request)
| Format | Edition (checked 2026-11-19) | Use in appaudit | Authority |
|--------|------------------------------|-----------------|-----------|
| SARIF | **2.1.0** (OASIS Standard, errata 01) | `findings.sarif`, code-located findings only. `security-severity` (CVSS score as a string) and `partialFingerprints` follow GitHub code-scanning conventions, not the OASIS text | docs.oasis-open.org/sarif/sarif/v2.1.0 · docs.github.com (SARIF support for code scanning) |
| OSCAL | **v1.2.x** (v1.2.3 latest checked) — Assessment Results and POA&M models | On request: assessment results + plan of action for FedRAMP-style or GRC tooling | pages.nist.gov/OSCAL |
| CSAF | **2.0** (OASIS; also ISO/IEC 20153:2025). 2.1 is a committee draft, do not emit it | On request: vendor advisory or VEX for a product the client ships | docs.oasis-open.org/csaf |
| CycloneDX | **1.7** (= ECMA-424 2nd edition) | On request: SBOM, VDR or VEX next to the SCA results | cyclonedx.org/specification · ecma-international.org |
| OpenCRE | Living mapping hub | `opencre[]` identifiers in findings.json | opencre.org |
| Office Open XML (SpreadsheetML) | ECMA-376 / ISO/IEC 29500 | `findings-register.xlsx`, written with the standard library | ecma-international.org |

## 2. Machine-readable feeds (used by `scripts/vuln_intel.py`)

| Feed | URL | Verified notes |
|------|-----|----------------|
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Fields: cveID, vendorProject, product, vulnerabilityName, dateAdded, shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse, notes, cwes |
| EPSS | `https://api.first.org/data/v1/epss?cve=…` | `cve` param ≤2,000 chars; lookup, not bulk (use daily CSV for bulk); report probability + percentile + date |
| NVD CVE API 2.0 | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=…` | 5 req / rolling 30 s without key; 50 with `apiKey` header; sleep ~6 s; handle 403 **and** 429, honour `Retry-After`. Since 15 Apr 2026 only prioritized CVEs are enriched |
| OSV.dev | `https://api.osv.dev/v1/query` | Aggregates GHSA among others |
| GitHub advisories | `GET https://api.github.com/advisories` | Global security advisories |
| ENISA EUVD | `https://euvd.enisa.europa.eu/` | Public API; manual lookup recommended until its API contract is pinned here |

## 3. Open checks (not confirmed from a primary source — verify before audit sign-off)

- Reg. (EU) 2026/1744: high-risk application dates (2 Dec 2027 Annex III / 2 Aug 2028 Annex I). Entry into force is confirmed on EUR-Lex; quote the application dates from the OJ article text before contractual use.

> **Naming note.** Two different OWASP agentic lists exist: the *Top 10 for Agentic Applications*
> (ASI01–ASI10, flagship GenAI Security Project) and the *Agentic Skills Top 10* (AST01–AST10,
> incubator). Cite the one you mean; do not merge them.

Resolved 2026-11-18: OWASP Top 10:2025 publication date (OWASP publishes none, see §1); ETSI TS 103 701 version (V2.1.1, 2025-05, confirmed on the ETSI PDF cover); CWE 2025 Top 10 KEV Weaknesses list (published on cwe.mitre.org); MASWE count (78, mas.owasp.org); ISVS count (OWASP sources conflict, so cite IDs only, see §1); CVSS example scores (the skill hard-codes none; compute every score with the FIRST v4.0 calculator at report time); BOD 19-02 status (revoked by BOD 26-04, 10 Jun 2026, as was BOD 22-01); AST10 titles (confirmed on OWASP pages; no OWASP-published release date); NIST IR 8547 timeline (confirmed in the final PDF); NCSC-NL webapplicaties guideline (updated edition confirmed on ncsc.nl).

## 4. Refresh procedure

1. At the start of an engagement with network access, run `vuln_intel.py` over all CVEs found
   in Phase 2; paste its table into the report's scoring section.
2. Quarterly, or whenever a report cites an edition: re-verify §1 against the Authority column,
   work through §3, bump `metadata.standards-checked` in SKILL.md and the date at the top of this file.
3. Record in the report whether the refresh ran (`threat_intel_refreshed` field).
