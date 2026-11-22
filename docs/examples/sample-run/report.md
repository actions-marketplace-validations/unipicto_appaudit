# Security Assessment — example-webshop-2026-11

**Date:** 2026-11-20  **Assessor:** Claude (appaudit) + operator  **Tool:** appaudit 4.4.0 (standards checked 2026-11-20, regulatory data checked 2026-11-20)

## 1. Executive summary

- **Overall posture:** High
- **Permission to test (declared by the assessor, not verified by appaudit):** signed-scope — SOW-2026-041 §3, signed 2026-11-18
- **Mode:** active · window 2026-11-20T09:00:00+01:00 to 2026-11-27T18:00:00+01:00
- **Tested scope:** staging.example.nl, *.staging.example.nl
- **Out of scope / not tested:** payments.staging.example.nl, Payment provider integration (out of scope), Mobile apps
- **Runtime capabilities used:** static review, shell, outbound HTTP
- **Threat-intel refresh:** 2026-11-20
- **Jurisdictions assessed:** EU, NL, UK, US · **not assessed:** none
- **Regulatory flags:** 2 may trigger now · 0 readiness (for client/counsel decision)
- **Totals:** 0 Critical, 1 High, 0 Medium, 1 Low, 0 Informational (Confirmed 2, Likely 0); SSVC 0 Act, 1 Attend, 0 Track*, 1 Track

One confirmed access-control flaw exposes other customers' orders, including names and addresses. It should be fixed before the next release, and counsel should decide on the GDPR and UK GDPR flags.

## 2. Findings

### [HIGH] AA-001 Order details of other customers readable by changing the order ID (BOLA)

- **Identifiers:** CWE-639; API1:2023, A01:2025
- **Severity:** CVSS-BTE (score pending: FIRST calculator) `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:P/CR:H` · [verify](https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator?vector=AV%3AN%2FAC%3AL%2FAT%3AN%2FPR%3AL%2FUI%3AN%2FVC%3AH%2FVI%3AN%2FVA%3AN%2FSC%3AN%2FSI%3AN%2FSA%3AN%2FE%3AP%2FCR%3AH&version=4.0)
- **Priority:** SSVC Attend (Exploitation public_poc / Automatable yes / Technical Impact partial / Mission & Well-being high) · EPSS — (—, —) · KEV No
- **Confidence:** Confirmed · verifier: Confirmed (Handler loads order by ID without owner check; evidence record 14 shows second test account's order returned.)
- **Asset / location:** Orders API · `src/api/orders.ts:42` · status open · owner Backend team
- **Description:** GET /api/orders/{id} returns any order to any logged-in user.
- **Proof (benign):**
  1. Log in as test account A and create order 1001.
  2. Log in as test account B and request GET /api/orders/1001.
  3. Order 1001 (account A) is returned; name and address fields redacted in evidence.
- **Root cause:** The handler fetches the order by primary key and never compares order.owner_id with the session user.
- **Impact:** Any customer can read every other customer's name, address and order history.
- **Remediation:** Scope the query by the caller's user ID.
  ```ts
  const order = await db.order.findFirst({ where: { id, ownerId: session.userId } });
  if (!order) return res.status(404).end();
  ```
  Regression note: Admin views need a separate, role-checked endpoint.
- **Remediation timeline:** organisation-defined — due 2026-12-04
- **Re-test:** Repeat step 2 with account B. → expected: 404 Not Found
- **Regulatory flags:** may_trigger_now: EU GDPR Art. 33 — 72 h after becoming aware of a personal-data breach; may_trigger_now: UK UK GDPR Art. 33 — 72 h after becoming aware of a personal-data breach (client/counsel decision)
- **Evidence:** log records 14

### [LOW] AA-002 Missing Content-Security-Policy on all origins

- **Identifiers:** CWE-1021; A02:2025
- **Severity:** CVSS-BTE (score pending: FIRST calculator) `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U` · [verify](https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator?vector=AV%3AN%2FAC%3AL%2FAT%3AP%2FPR%3AN%2FUI%3AA%2FVC%3AL%2FVI%3AL%2FVA%3AN%2FSC%3AN%2FSI%3AN%2FSA%3AN%2FE%3AU&version=4.0)
- **Priority:** SSVC Track (Exploitation none / Automatable no / Technical Impact partial / Mission & Well-being medium) · EPSS — (—, —) · KEV No
- **Confidence:** Confirmed · verifier: Confirmed (Response headers in evidence record 3.)
- **Asset / location:** Web front-end · `https://staging.example.nl/` · status open · owner Front-end team
- **Root cause:** —
- **Impact:** —
- **Remediation:** Add the header baseline from module-web.md §D.
  ```http
  Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
  ```
- **Remediation timeline:** organisation-defined — due 2027-02-18
- **Re-test:** curl -sI https://staging.example.nl/ → expected: Content-Security-Policy present
- **Regulatory flags:** none (client/counsel decision)
- **Evidence:** log records 3

## 3. Informational / hardening

- None.

## 4. Verified not applicable

- CVE-2025-29927 (Next.js middleware bypass) — Application does not use Next.js middleware for authorization.
- NY GBL § 899-aa breach notice — Exposed fields (name, address, order history) are not 'private information' under § 899-aa(1)(b) without an identifier such as SSN, driver's licence or account number with access code.

## 5. Re-test plan

| Finding | Re-test action | Expected result |
|---|---|---|
| AA-001 | Repeat step 2 with account B. | 404 Not Found |
| AA-002 | curl -sI https://staging.example.nl/ | Content-Security-Policy present |

## 6. Regulatory trigger register

For client/counsel decision. The Tier column keeps the two tiers apart.

| Finding | Tier | Jurisdiction | Instrument | Provision | Deadline | Basis | Source checked |
|---|---|---|---|---|---|---|---|
| AA-001 | may_trigger_now | EU | GDPR | Art. 33 | 72 h after becoming aware of a personal-data breach | client is controller; personal data of EU customers was reachable; access by third parties not yet ruled out | 2026-11-18 |
| AA-001 | may_trigger_now | UK | UK GDPR | Art. 33 | 72 h after becoming aware of a personal-data breach | client is controller for UK customers; personal data was reachable; access by third parties not yet ruled out | 2026-11-19 |

Jurisdictions not assessed: none.

## 7. Disclosure routing and conflicts

- No third-party disclosure recommended.

## 8. Evidence & data handling

- Raw evidence stored at: .appaudit/evidence on the assessor's encrypted laptop; access: Assessor and client security officer
- Evidence log: 0 records; chain not used; calls blocked by the scope guard: 0
- Secrets discovered: 0, all redacted; rotation recommended for: none

## Appendix — build checks and version

- Update check: not_published
- Update source answered HTTP 404.
- Warning: AA-001: CVSS vector given without a score; compute it with the FIRST v4.0 calculator
- Warning: AA-002: CVSS vector given without a score; compute it with the FIRST v4.0 calculator
- SHA-256 of every deliverable: `MANIFEST.sha256`
