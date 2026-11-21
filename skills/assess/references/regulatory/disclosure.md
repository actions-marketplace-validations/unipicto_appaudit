# Vulnerability disclosure routing and conflicts

Checked 2026-11-20. Use when a finding affects software or a product the client does **not**
own, or when the client is the vendor and must handle a report.

## Channels

| Jurisdiction | Channel | Notes |
|--------------|---------|-------|
| Any | Vendor's `security.txt` (RFC 9116), bug-bounty programme, PSIRT | First contact; ISO/IEC 29147 (disclosure) and 30111 (handling) |
| EU | National CSIRT as CVD coordinator (NIS2 Art. 12); ENISA EUVD | CRA Art. 14: manufacturers report actively exploited vulnerabilities via the ENISA single reporting platform (24 h early warning) |
| Netherlands | NCSC-NL (Leidraad CVD); DIVD | — |
| United States | CISA coordinated vulnerability disclosure; CERT/CC | — |
| United Kingdom | NCSC vulnerability reporting | — |
| Canada | Canadian Centre for Cyber Security (CCCS) | — |
| Australia | ASD's ACSC (cyber.gov.au) | — |
| Singapore | SingCERT (CSA) | — |
| Japan | IPA (reports) and JPCERT/CC (coordination): Information Security Early Warning Partnership | Aligned with ISO/IEC 29147; JVN publishes coordinated advisories |
| India | CERT-In (Responsible Vulnerability Disclosure and Coordination policy) | A related incident may also fall under the CERT-In 6-hour reporting duty |
| **China** (warning only) | MIIT Cybersecurity Threat and Vulnerability Information Sharing Platform (cstis.cn) | Under the Regulations on the Management of Network Product Security Vulnerabilities (2021), network product providers in China must report vulnerabilities in their products to MIIT **within 2 days**; publishing vulnerability details before a fix is restricted. Applies to entities operating in mainland China, including foreign-invested enterprises |

## Conflict check — flag to counsel, do not resolve

Flag a conflict when deadlines or confidentiality duties cannot all be met, for example:
- A client with China operations (vendor) under the 2-day MIIT duty while the CVD agreement with an
  external researcher or another vendor sets an embargo.
- CRA 24 h early warning for an actively exploited vulnerability while a vendor embargo is still
  running.
- A bug-bounty programme's terms forbid disclosure that a regulator may require.

Record in `findings.json → disclosure[]`: channel, deadline, the conflict, and
`decided_by: client/counsel`.
