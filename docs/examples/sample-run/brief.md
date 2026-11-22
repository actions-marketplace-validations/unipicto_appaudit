# Security assessment brief — example-webshop-2026-11

**Target:** staging.example.nl (web shop and API) · **Date:** 2026-11-20 · **Assessor:** Claude (appaudit) + operator  
**Permission to test (declared by the assessor, not verified by appaudit):** signed-scope (SOW-2026-041 §3, signed 2026-11-18) · **Mode:** active · **Tool:** appaudit 4.4.0 (standards checked 2026-11-20, regulatory data checked 2026-11-20)

One confirmed access-control flaw exposes other customers' orders, including names and addresses. It should be fixed before the next release, and counsel should decide on the GDPR and UK GDPR flags.

## 1. Deadlines that may be running

For client/counsel decision. The plugin does not decide materiality or awareness.

| Finding | Jurisdiction | Instrument | Deadline | Clock starts | Authority |
|---|---|---|---|---|---|
| AA-001 | EU | GDPR Art. 33 | 72 h after becoming aware of a personal-data breach | when the controller becomes aware a breach occurred | Autoriteit Persoonsgegevens |
| AA-001 | UK | UK GDPR Art. 33 | 72 h after becoming aware of a personal-data breach | when the controller becomes aware a breach occurred | Information Commissioner's Office (ICO) |

## 2. Overall posture

**High**

| Severity | Confirmed | Likely | Total |
|---|---|---|---|
| High | 1 | 0 | 1 |
| Low | 1 | 0 | 1 |

SSVC: Act 0 · Attend 1 · Track* 0 · Track 1

## 3. Top risks

| ID | Title | Severity (CVSS-BTE) | SSVC | KEV | Fix due |
|---|---|---|---|---|---|
| AA-001 | Order details of other customers readable by changing the order ID (BOLA) | High | Attend | No | 2026-12-04 |
| AA-002 | Missing Content-Security-Policy on all origins | Low | Track | No | 2027-02-18 |

## 4. Decisions needed

- Decide whether order data of other customers was accessed by anyone other than the assessor (log review).
- Decide on GDPR (EU) for AA-001: client is controller; personal data of EU customers was reachable; access by third parties not yet ruled out.
- Decide on UK GDPR (UK) for AA-001: client is controller for UK customers; personal data was reachable; access by third parties not yet ruled out.

## 5. Prepare for

- Nothing flagged.

## 6. Coverage

- Jurisdictions assessed: EU, NL, UK, US
- **Jurisdictions not assessed:** none
- Not tested: Payment provider integration (out of scope); Mobile apps
- Calls blocked by the scope guard: 0

## 7. Integrity and version

- Evidence log: not used
- Update check: not_published
- SHA-256 of every deliverable: `MANIFEST.sha256`
- Build warnings: 2 (see report appendix)
