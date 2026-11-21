# United Kingdom

Checked 2026-11-19. Primary sources: legislation.gov.uk, ico.org.uk, bills.parliament.uk,
gov.uk.

| Instrument | Applies to (role) | What a finding can trigger | Deadline | Authority / channel | Tier · status |
|------------|-------------------|----------------------------|----------|---------------------|---------------|
| **UK GDPR** Arts. 33–34 + Data Protection Act 2018 (as amended by the Data (Use and Access) Act 2025) | `controller` (processor → controller without undue delay) | Personal-data breach likely to result in a risk to rights and freedoms | ICO without undue delay, **≤72 h** after awareness where feasible; individuals without undue delay if high risk | ICO (online form) | `may_trigger_now` |
| **NIS Regulations 2018** reg. 11 (OES) / reg. 12 (RDSP) | `uk_oes`, `uk_rdsp` | NIS incident with significant (OES) or substantial (RDSP) impact | Without undue delay, **≤72 h** after awareness | OES: sector competent authority; RDSP: ICO | `may_trigger_now` |
| **Cyber Security and Resilience (NIS) Bill** | Expands NIS to MSPs, data centres, critical suppliers, large load controllers | Significant incident | Initial notification **24 h**, full report **72 h** (copy to NCSC) | Regulator + NCSC | `readiness` — passed the Commons 10 Jun 2026; in the Lords; Royal Assent expected late 2026, duties through secondary legislation to ~2028 |
| **Product Security and Telecommunications Infrastructure Act 2022** + 2023 Regulations (PSTI) | Consumer connectable product `manufacturer`, importer, distributor | No universal default passwords; vulnerability-disclosure policy; declared support period | — | Office for Product Safety and Standards | In force since 29 Apr 2024 (conformity; verify against legislation.gov.uk before contractual use) |

## Testing law and disclosure

- Computer Misuse Act 1990: `testing-law.md`. A statutory defence for security research is being
  added via the National Security Bill and is reported to be narrow (scanning internet-facing
  systems). Written authorization remains the only reliable basis.
- NCSC vulnerability reporting; vendors' security.txt (RFC 9116).
