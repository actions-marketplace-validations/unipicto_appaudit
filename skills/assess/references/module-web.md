# Module — Web Applications & Front-End

**Standards:** OWASP Top 10:2025 (final; cite without a publication date, see standards.md), OWASP ASVS 5.0.0 (30 May 2025; cite requirements as
v5.0.0-x.y.z), CWE (2025 CWE Top 25 for prevalence), RFC 8725 (JWT BCP), NIST SP 800-63B-4
(Aug 2025), NIST SP 800-52 Rev. 2, NCSC-NL ICT-beveiligingsrichtlijnen voor webapplicaties
and voor TLS (v2.1), BSI TR-02102-2. OWASP Cheat Sheets: Input Validation, Mass Assignment,
Query Parameterization, NoSQL Security, Database Security, Third Party Payment Gateway
Integration, Transaction Authorization. PCI DSS v4.0.1 Req. 6.4.3 / 11.6.1 (payment-page
scripts) where the client's PCI scope includes them. Acceptance checklist:
the client's own checklist when provided (SKILL.md §6).

Map every finding to an OWASP 2025 category so reports stay comparable across engagements:

| OWASP 2025 | Category | Typical checks in this module |
|------------|----------|-------------------------------|
| A01 | Broken Access Control (incl. SSRF) | IDOR/BOLA, forced browsing, privilege escalation, SSRF to internal/metadata endpoints |
| A02 | Security Misconfiguration | Headers, CORS, debug mode, verbose errors, exposed files, default creds |
| A03 | Software Supply Chain Failures | See `module-api-supply-chain.md` (SCA, build pipeline) |
| A04 | Cryptographic Failures | Cleartext transport, weak algorithms, hardcoded keys, poor TLS config |
| A05 | Injection | Server-side input validation, SQLi, NoSQL operator injection, XSS (reflected/stored/DOM), command, template (SSTI), LDAP |
| A06 | Insecure Design | Missing rate limits on sensitive flows, weak auth state machines, multi-tenant gaps, price and payment tampering |
| A07 | Authentication Failures | Credential stuffing exposure, session handling, MFA gaps, reset-token weakness |
| A08 | Software or Data Integrity Failures | Unsafe deserialization, unverified updates, CI/CD trust |
| A09 | Security Logging and Alerting Failures | Missing auth/authz/event logging, no alerting, PII in logs |
| A10 | Mishandling of Exceptional Conditions | Unhandled errors leaking state, insecure fallback |

---

## A. Authentication & sessions (A07, A04)

- [ ] Password storage (OWASP Password Storage Cheat Sheet): Argon2id (minimum m=19 MiB, t=2, p=1); scrypt (N=2^17, r=8, p=1); bcrypt (cost ≥10, 72-byte input limit) for legacy only; PBKDF2-HMAC-SHA256 ≥600,000 iterations where FIPS is required. Per-user salt; no MD5/SHA-1/plain.
- [ ] NIST SP 800-63B-4: no composition rules; check new passwords against a blocklist; phishing-resistant authenticator required at AAL3 and offered at AAL2.
- [ ] MFA available for privileged and account-recovery flows.
- [ ] Session cookies: `HttpOnly`, `Secure`, `SameSite=Strict|Lax`; prefer the `__Host-` prefix (requires `Secure`, `Path=/`, no `Domain`); rotated on login and privilege change; invalidated on logout and password change.
- [ ] Tokens not stored in `localStorage`/`sessionStorage` when `HttpOnly` cookies are feasible.
- [ ] JWT (RFC 8725 / BCP 225): allow-list algorithms, reject `none`, bind key to algorithm (no alg confusion), validate `iss`/`aud`/`exp`/`nbf`, explicit `typ`; short lifetimes, refresh rotation.
- [ ] Password reset: high-entropy single-use token, short expiry, no user enumeration via response differences or timing.
- [ ] Rate limiting / lockout on login, reset, MFA, and signup.

## B. Authorization & access control (A01)

- [ ] Every object access checks ownership/tenancy server-side (IDOR / BOLA). Test by swapping identifiers between two test accounts you control.
- [ ] Function-level authZ on admin and bulk endpoints; UI hiding is not a control.
- [ ] Admin routes restricted (network/VPN/zero-trust) and separately authenticated.
- [ ] SSRF: user-controlled URLs are allow-listed by scheme/host; cloud metadata endpoints blocked; redirects not followed blindly.
- [ ] Horizontal/vertical escalation paths via parameter tampering, mass assignment, or role flags in client state.

## C. Input handling & injection (A05, A08)

Server-side validation (OWASP Input Validation Cheat Sheet). Client-side checks are UX only;
an attacker sends requests directly.
- [ ] Every request body, query string, header, path parameter, cookie and uploaded-file field is validated **on the server** against an explicit schema (type, length, range, format, allowed values) before business logic runs. Shared libraries such as zod, Joi, Pydantic, Bean Validation or JSON Schema count when applied at every entry point, including webhooks, queue consumers and internal APIs.
- [ ] Allow-list, not deny-list: reject on failure rather than "cleaning" input; unknown fields rejected or stripped (closes mass assignment, see API3 and the Mass Assignment Cheat Sheet).
- [ ] Input decoded and canonicalized (Unicode normalization, URL/percent decoding) once, before validation, so double-encoding cannot bypass checks.
- [ ] Validation failures return a generic error and are logged (section F); they never echo the raw value back unencoded.
- [ ] Validation is not the injection or XSS control: parameterized queries and output encoding below are still required.

Injection and related flaws:
- [ ] Database access via parameterized queries / ORM; no string-built SQL. Audit ORM raw-query APIs (`raw()`, `$queryRawUnsafe`, `sequelize.query`, `text()` with f-strings) and dynamic `ORDER BY`/column names (allow-list them; they cannot be bound as parameters).
- [ ] NoSQL operator injection: request JSON cannot inject query operators (e.g. MongoDB `$ne`, `$gt`, `$where`); cast to expected primitive types before querying (OWASP NoSQL Security Cheat Sheet).
- [ ] Output encoding is context-aware (HTML, attribute, JS, URL, CSS); templates auto-escape; no `innerHTML`/`dangerouslySetInnerHTML` on untrusted data.
- [ ] DOM-XSS sinks (`location.hash`, `document.write`, `eval`, `setTimeout(string)`) audited.
- [ ] Server-side template injection: user input never reaches template compilation.
- [ ] Command/path injection: no shell interpolation; file paths normalized and jailed.
- [ ] Deserialization of untrusted data avoided or type-restricted.
- [ ] File upload: magic-byte validation, extension allow-list, size cap, re-encode images, stored outside web root, served from isolated origin.
- [ ] CSRF: tokens on state-changing requests, or `SameSite` + custom-header pattern for APIs.

## D. Configuration & headers (A02, A04)

Expected header baseline (OWASP Secure Headers Project / HTTP Headers Cheat Sheet; verify
presence and values on every origin and subdomain):

```http
Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), camera=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
X-Frame-Options: DENY            # legacy browsers only; CSP frame-ancestors is authoritative
```

- Add `preload` to HSTS **only** after meeting hstspreload.org requirements (max-age ≥31536000, includeSubDomains, HTTPS on every subdomain).
- Add `Cross-Origin-Embedder-Policy: require-corp` only where cross-origin isolation is needed.
- Do **not** set `X-XSS-Protection` (or set it to `0`); the legacy filter is deprecated.

- [ ] TLS 1.3 preferred, TLS 1.2 minimum with AEAD suites (NIST SP 800-52 Rev. 2; NCSC-NL TLS v2.1 rates 1.3 "Good", 1.2 "Sufficient", 1.0/1.1 "Phase out"); HTTP → HTTPS redirect; valid chain.
- [ ] Crypto (A04): no ECB, DES/3DES, RC4, MD5/SHA-1 for security uses; AES-GCM / ChaCha20-Poly1305; RSA ≥3072 for new long-lived keys (2048 minimum), ECC P-256+ (NIST SP 800-131A Rev. 2; BSI TR-02102-1).
- [ ] Post-quantum readiness (Informational unless the client has a mandate): crypto inventory / CBOM exists; plan to migrate to FIPS 203 ML-KEM / FIPS 204 ML-DSA / FIPS 205 SLH-DSA; hybrid KEM in TLS where supported. NIST IR 8547 sets deprecation of quantum-vulnerable algorithms after 2030 and disallowance after 2035 — quote the final PDF text in contractual deliverables.
- [ ] CORS: no wildcard origin with credentials; origin allow-list; minimal methods/headers.
- [ ] Debug/dev mode off; stack traces and framework error pages disabled in prod.
- [ ] No exposed `.git/`, `.env`, backups, source maps with secrets, admin consoles, or unlinked staging pages.
- [ ] Directory listing off; default accounts removed.
- [ ] Client bundle free of API keys, internal hostnames, debug comments.

## E. Business logic & design (A06, A10)

- [ ] Price/quantity/total recomputed server-side; client values never trusted.
- [ ] Multi-step workflows cannot be skipped or replayed out of order.
- [ ] Race conditions on balance/coupon/vote endpoints (idempotency keys, locking).
- [ ] Error paths fail closed; exceptions do not leak internal state.

### Prices and payments (A06, A08)

Use test-mode keys and the payment provider's sandbox only. Never place real payments or
alter live orders to prove a finding.
- [ ] The amount charged is computed on the server from server-side catalogue prices, quantities, discounts, tax and shipping; the client sends item IDs and quantities, never prices or totals. Currency and minor-unit rounding handled server-side.
- [ ] Quantities validated as positive integers within limits (negative or zero quantities, overflow and fractional values rejected); coupons and vouchers are single-use or rate-limited, checked server-side, and cannot stack beyond policy.
- [ ] Order is marked paid **only** from the provider's verified server-side signal (signed webhook or a server-to-server status lookup), never from the browser redirect or a client-side "success" callback.
- [ ] Webhook endpoint verifies the provider's signature with the provider's official library or documented algorithm over the **raw** request body, rejects stale timestamps (replay window), and uses a webhook secret held server-side only.
- [ ] Webhook and payment handlers are idempotent on the provider's event or payment ID (a replayed or duplicated event cannot fulfil an order twice); the paid amount and currency in the event are compared with the stored order before fulfilment.
- [ ] Refunds, payouts, price changes and other high-value actions need step-up authentication or a second approver where the business requires it (OWASP Transaction Authorization Cheat Sheet).
- [ ] No card data (PAN, CVC) touches the client's servers or logs unless the PCI scope covers it; hosted fields or redirect checkout preferred (OWASP Third Party Payment Gateway Integration Cheat Sheet). Payment-page scripts inventoried, authorized and integrity-checked where PCI DSS v4.0.1 Req. 6.4.3 / 11.6.1 apply.

### Validation for prices and payments
A tampered request in the provider's test mode that is rejected, or an order total the
server recomputes, is the proof. Report a webhook without signature checks as `Confirmed`
from code; do not send forged events to a live endpoint.

## F. Logging & alerting (A09)

- [ ] Auth success/failure, authZ denials, validation failures, admin actions logged with correlation IDs.
- [ ] Logs exclude credentials, tokens, full PII, card data.
- [ ] Alerting exists for anomaly spikes (failed logins, injection patterns).

## G. Database & data layer (A01, A02, A04, A05)

OWASP Database Security Cheat Sheet; CIS Benchmark for the engine and version in scope.
Review configuration and grants read-only; never change a production database to test.
- [ ] **Not exposed:** the database port is reachable only from the application tier (private subnet, security group, firewall); no public IP; admin consoles (phpMyAdmin, Adminer, Mongo Express, cloud query editors) not internet-facing.
- [ ] **Least-privilege accounts:** the application connects with an account that has only the DML it needs on its own schema; no superuser, `DBA`, `db_owner`, `SUPER`, or DDL rights at runtime. Migrations run under a separate account. Read-only paths (reporting, analytics) use a read-only account.
- [ ] **No default or shared credentials:** default accounts disabled or renamed; each service has its own credential; credentials come from a secrets manager or environment injection (see `module-api-supply-chain.md` Part 4), never from source code.
- [ ] **Encrypted in transit with verification:** TLS between app and database with certificate and hostname checks (e.g. PostgreSQL `sslmode=verify-full`; `sslmode=require` alone does not verify the server).
- [ ] **Encrypted at rest:** storage/volume encryption on; especially sensitive columns (national ID numbers, health data, tokens) additionally encrypted or tokenized at application level with keys outside the database.
- [ ] **Tenant isolation:** multi-tenant data separated by schema/database or enforced row-level security (e.g. PostgreSQL RLS), not only by a `WHERE tenant_id = ?` the code might forget.
- [ ] **Backups:** encrypted, access-restricted (separate credentials/account), not stored on public storage, retention matches the privacy policy, and a restore has been tested.
- [ ] **Auditing:** logins, privilege changes, schema changes and bulk exports logged and sent off the database host (section F).
- [ ] **Engine patched** to a supported version; risky features off (e.g. `xp_cmdshell`, `LOAD DATA LOCAL`, unauthenticated Redis/MongoDB/Elasticsearch, `trust` auth in `pg_hba.conf`).

---

## Validation guidance (Phase 3)

Confirm with the least intrusive proof: for XSS a harmless reflected marker you
control; for IDOR, access to a record owned by *your second test account*; for
header/config issues, the response itself is the proof. Mark `Likely` when you can
see the flaw in code but cannot safely exercise it.

## Common remediations (copy-paste starting points)

- **Parameterized query** — use the framework's placeholder API; never concatenate.
- **Cookie flags** — `Set-Cookie: session=…; HttpOnly; Secure; SameSite=Lax; Path=/`
- **CORS** — reflect only origins from an explicit allow-list; omit `Access-Control-Allow-Credentials` unless required.
- **Object-level authZ** — load the object *scoped to the caller* (`WHERE id = ? AND owner_id = ?`) rather than loading then checking.
- **Server-side schema validation** (TypeScript + zod; same idea in any language):
  ```ts
  const OrderInput = z.object({
    items: z.array(z.object({
      sku: z.string().regex(/^[A-Z0-9-]{3,32}$/),
      qty: z.number().int().min(1).max(100),
    })).min(1).max(50),
  }).strict();                       // unknown fields (e.g. "price") are rejected
  const input = OrderInput.parse(req.body); // throws → 400 with a generic message
  ```
- **Least-privilege database role** (PostgreSQL; adapt names):
  ```sql
  CREATE ROLE app_rw LOGIN PASSWORD :'from_secrets_manager';
  REVOKE ALL ON SCHEMA public FROM PUBLIC;
  GRANT USAGE ON SCHEMA app TO app_rw;
  GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app TO app_rw;
  -- no CREATE, no superuser; migrations use a separate role
  ```
- **Payment fulfilment** — fulfil only inside the verified-webhook handler: verify signature on the raw body → look up the order → compare amount and currency → record the event ID (unique constraint) → fulfil. Return `2xx` for already-processed event IDs without fulfilling again.
