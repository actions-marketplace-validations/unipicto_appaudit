# Canada (federal)

Checked 2026-11-19. Primary sources: laws-lois.justice.gc.ca, priv.gc.ca, osfi-bsif.gc.ca,
canada.ca (Public Safety), parl.ca (LEGISinfo). Provincial privacy laws (e.g. Québec Law 25,
Alberta PIPA) are **not covered** in this version — list them as "not assessed".

| Instrument | Applies to (role) | What a finding can trigger | Deadline | Authority / channel | Tier · status |
|------------|-------------------|----------------------------|----------|---------------------|---------------|
| **PIPEDA** s. 10.1 + Breach of Security Safeguards Regulations | `controller` (organization in control of personal information in commercial activity) | Breach of security safeguards creating a **real risk of significant harm** (RROSH) | **As soon as feasible** after determining the breach occurred; record **every** breach (24 months) | Office of the Privacy Commissioner (OPC) | `may_trigger_now` |
| **OSFI Technology and Cyber Security Incident Reporting Advisory** (2021; form updated Apr 2025) | `ca_frfi` | Technology or cyber incident meeting OSFI criteria (e.g. protocols activated, reported to board/OPC/law enforcement) | **Within 24 h, or sooner if possible**; subsequent updates | OSFI Technology Risk Division + Lead Supervisor | `may_trigger_now` |
| **Critical Cyber Systems Protection Act** (Bill C-8, S.C. 2026, c. 9) | `ca_designated_operator` (finance, telecom, energy, transport under federal jurisdiction) | Cyber incident affecting a critical cyber system | Prescribed period, **max 72 h** | Communications Security Establishment (CSE) | `readiness` — Royal Assent 15 Jun 2026; CCSPA provisions phased in by order/regulation. Telecommunications Act amendments in force on assent |

## Testing law and disclosure

- Criminal Code ss. 342.1 and 430(1.1): `testing-law.md`.
- Canadian Centre for Cyber Security (CCCS) for vulnerability coordination.
