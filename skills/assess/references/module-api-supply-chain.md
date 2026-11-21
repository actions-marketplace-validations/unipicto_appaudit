# Module — APIs & Software Supply Chain (SCA / Secrets / IaC)

**Standards:** OWASP API Security Top 10 (2023 — latest edition as of 18 Nov 2026; re-check
owasp.org/API-Security before each engagement), OWASP Top 10:2025 A03 (Supply Chain) & A08
(Integrity), CWE, NIST SSDF SP 800-218 v1.1 (v1.2 draft Dec 2025), SLSA v1.1+, OpenSSF
Scorecard, CycloneDX 1.6+ (ECMA-424) / SPDX 3.0.x, CISA 2025 SBOM Minimum Elements,
CIS Controls v8.1 Control 7, NSA/CISA Kubernetes Hardening Guide v1.2, K8s Pod Security Standards,
OWASP Cheat Sheets: Secrets Management, NPM Security, Nodejs Security.

---

## Part 1 — API security (REST / GraphQL / gRPC)

| ID (2023) | Risk | What to check |
|-----------|------|---------------|
| API1 | Broken Object Level Authorization (BOLA) | Swap object IDs between two test identities; check every read/write/delete |
| API2 | Broken Authentication | Token validation, key rotation, weak/absent auth on "internal" routes, credential stuffing exposure |
| API3 | Broken Object Property Level Authorization | Excessive data exposure in responses; mass assignment on writes (unexpected fields accepted) |
| API4 | Unrestricted Resource Consumption | Missing rate limits, pagination caps, payload size limits, expensive GraphQL queries |
| API5 | Broken Function Level Authorization | Admin/bulk/export functions reachable by normal roles; HTTP method tampering |
| API6 | Unrestricted Access to Sensitive Business Flows | Automation-prone flows (checkout, signup, referral) without anti-abuse controls |
| API7 | Server-Side Request Forgery | User-supplied URLs fetched server-side without allow-listing |
| API8 | Security Misconfiguration | CORS, verbose errors, default creds, unpatched stack, missing TLS |
| API9 | Improper Inventory Management | Shadow/legacy/debug versions (`/v1`, `/beta`, `/internal`) still live |
| API10 | Unsafe Consumption of APIs | Upstream responses trusted without validation; redirects followed blindly |

### GraphQL-specific
- [ ] Introspection disabled in prod (or restricted); schema not leaking internal types.
- [ ] Query depth/complexity/cost limits; batching and aliasing abuse limited.
- [ ] Field-level authZ on resolvers, not only at the operation level.

### gRPC-specific
- [ ] TLS enforced; mTLS for service-to-service; reflection disabled in prod.
- [ ] Per-method authZ interceptors; message size limits.

### Validation guidance
Prove BOLA/BFLA with two accounts you control and a benign read. For rate-limit gaps,
a small burst well under the scope's cap that shows no throttling header/response is
sufficient evidence — do not demonstrate exhaustion.

---

## Part 2 — Software Composition Analysis & secrets

- [ ] Generate or obtain an SBOM (CycloneDX 1.6+ or SPDX 3.0.x); resolve **transitive** dependencies, not only direct.
- [ ] Map components to CVEs (OSV.dev — includes GHSA; GitHub `GET /advisories`; NVD API 2.0; ENISA EUVD for EU scope); run `scripts/vuln_intel.py` on each CVE for KEV/EPSS/CVSS. Where NVD lacks enrichment, use the CNA / CISA-ADP score.
- [ ] Check **reachability** where tooling allows — is the vulnerable function actually called? Reachable + KEV = top priority.
- [ ] Flag unmaintained, typosquat-prone, or recently-transferred packages; verify publisher signatures/provenance (Sigstore, npm provenance).
- [ ] Lockfiles committed and honoured in CI; no floating version ranges for prod builds.
- [ ] **Unused and unnecessary packages removed.** Every dependency is attack surface (install scripts, transitive CVEs) even when no code imports it. Detect with the ecosystem's analyser and confirm by reading the code before removing:

  | Ecosystem | Find unused | Keep dev tools out of production |
  |-----------|-------------|----------------------------------|
  | JavaScript/TypeScript | `npx knip` or `npx depcheck` | `npm ci --omit=dev` (or `pnpm install --prod`) in the production image |
  | Python | `deptry .` | Separate runtime and dev requirement files / dependency groups |
  | Go | `go mod tidy` (diff shows removals) | Build static binary; ship no toolchain |
  | Rust | `cargo machete` or `cargo +nightly udeps` | `[dev-dependencies]` stay out of release builds |
  | Java (Maven) | `mvn dependency:analyze` ("Unused declared") | `test`/`provided` scopes |
  | .NET | IDE "Remove unused references" / `dotnet list package` review | Exclude test and analyser packages from publish |
  | Container OS | Image SBOM review (`docker scout sbom` or Syft) | Multi-stage build; distroless or minimal base; no compilers, shells, package managers in the runtime image where feasible |

  Report unused packages as **Informational** (hardening) unless the unused package has a known vulnerability, an install script, or was recently transferred to a new maintainer; then rate the finding on that risk. Analysers produce false positives (dynamic imports, plugins loaded by name, CLI tools used in scripts): mark `Likely` until a build and test run passes without the package.
- [ ] Secrets scan across working tree **and git history** (keys, tokens, certs, connection strings). Report as redacted fragments; recommend rotation + history rewrite + revocation.
- [ ] CI/CD: third-party actions/plugins pinned to **full-length commit SHAs** — tag pinning is insufficient (Trivy, CVE-2026-33634: 76 of 77 `trivy-action` tags force-pushed to malicious code, Mar 2026). Least-privilege `GITHUB_TOKEN`, no secrets in logs, protected branches, signed commits/artifacts (Sigstore) where feasible.

## Part 3 — Infrastructure-as-Code & containers

- [ ] Dockerfile: non-root user, pinned base image digest, no secrets in layers/ARGs, minimal image, `HEALTHCHECK`.
- [ ] Kubernetes: Pod Security Standards `restricted`; no privileged pods, `runAsNonRoot`, `readOnlyRootFilesystem`, resource limits, network policies, RBAC least privilege, secrets not in plain ConfigMaps. Benchmark against the CIS Kubernetes/Docker Benchmark version for the distro in scope.
- [ ] Terraform/CloudFormation: no `0.0.0.0/0` on sensitive ports, encryption at rest flags, public bucket/blob checks, IAM wildcards, logging enabled.
- [ ] Cloud metadata endpoint (`169.254.169.254` / equivalent) unreachable from app code paths; AWS IMDSv2 required (`HttpTokens=required`) or the provider's equivalent.
- [ ] Scanner binaries (Trivy, Checkov, etc.) verified by checksum/signature before use.

## Part 4 — Environment variables & runtime configuration

OWASP Secrets Management Cheat Sheet; Twelve-Factor "config in the environment" is fine for
non-secret settings, but secrets need more protection than a plain environment variable gives.
- [ ] **Inventory:** list every variable the app reads (`process.env`, `os.environ`, `os.Getenv`, `System.getenv`, `.env*` files, Docker `ENV`/`ARG`, Compose `environment:`, Kubernetes `env:`/`envFrom:`, CI variables). Each is classified as secret or non-secret, with an owner.
- [ ] **Nothing secret in client-exposed variables.** Build tools inline variables with public prefixes into the browser bundle: `NEXT_PUBLIC_*` (Next.js), `VITE_*` (Vite), `REACT_APP_*` (Create React App), `PUBLIC_*` (SvelteKit/Astro), `EXPO_PUBLIC_*` (Expo). Search the built bundle for key patterns as proof.
- [ ] **`.env` files never committed:** `.env*` in `.gitignore` (except a value-free `.env.example`); git history scanned (Part 2); `.env` not copied into images (`.dockerignore`) or served by the web server (`module-web.md` D).
- [ ] **No secrets in image metadata:** not in `ENV`/`ARG`/`LABEL` (visible via `docker history` and `docker inspect`); use BuildKit secret mounts at build time and runtime injection from a secrets manager.
- [ ] **Production secrets come from a secrets manager** (cloud KMS-backed store, HashiCorp Vault, Kubernetes Secrets with encryption at rest and RBAC, or a sealed/external-secrets operator), are scoped per environment and service, and are rotated. Dev, test and production never share a secret.
- [ ] **Fail fast and safe:** the app validates required variables at startup with a schema (types, allowed values) and refuses to start if one is missing; no insecure defaults (e.g. `DEBUG=true`, `NODE_ENV` unset, a fallback JWT secret like `"changeme"`, `ALLOWED_HOSTS=*`).
- [ ] **Production flags correct:** `NODE_ENV=production`, `DEBUG=False` / `APP_DEBUG=false`, `ASPNETCORE_ENVIRONMENT=Production`, framework secret keys set and unique per environment.
- [ ] **Not leaked at runtime:** variables are not printed by startup logs, crash reporters, `/debug`, `/env`, `/actuator/env`, `phpinfo()` or health endpoints; CI masks secrets in logs; child processes and third-party SDKs receive only the variables they need.

Validation: a secret found in a bundle, image layer, log or public endpoint is `Confirmed`.
Report it redacted (last 4 characters) and recommend rotation, as for any leaked secret.

## Remediation patterns
- **Startup config validation** (Node.js + zod):
  ```ts
  const Env = z.object({
    NODE_ENV: z.enum(["production", "staging", "development"]),
    DATABASE_URL: z.string().url(),
    JWT_SECRET: z.string().min(32),
  });
  export const env = Env.parse(process.env); // crash at boot if missing or weak
  ```
- **Mass assignment** — bind requests to explicit DTOs/allow-lists; never bind directly to ORM models.
- **BOLA** — scope every query by caller identity at the data layer.
- **Rate limiting** — token bucket per identity + per IP; return `429` with `Retry-After`.
- **Dependency CVE** — upgrade to the fixed version from the vendor advisory; if no fix, isolate/disable the vulnerable path and document the risk acceptance with an expiry.
