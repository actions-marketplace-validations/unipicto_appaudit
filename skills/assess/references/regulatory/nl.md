# Netherlands (national layer on top of `eu.md`)

Checked 2026-11-18 against officielebekendmakingen.nl, ncsc.nl and autoriteitpersoonsgegevens.nl.

| Instrument | Applies to (role) | What a finding can trigger | Deadline | Authority / channel | Tier · status |
|------------|-------------------|----------------------------|----------|---------------------|---------------|
| **Cyberbeveiligingswet (Cbw) + Cyberbeveiligingsbesluit**, Stb. 2026, 189 (NIS2 transposition; replaces the Wbni) | `essential_entity`, `important_entity` | Significant incident | Early warning ≤24 h · notification ≤72 h · final report ≤1 month | CSIRT (NCSC-NL or sector CSIRT) and the sector's competent authority | `may_trigger_now` since **15 Aug 2026** (board-training duty transition to 15 Aug 2028) |
| **GDPR / UAVG** | `controller` | Personal-data breach | ≤72 h | **Autoriteit Persoonsgegevens** (meldloket datalekken) | `may_trigger_now` |

## Technical guidance auditors expect

| Guidance | Use for |
|----------|---------|
| NCSC-NL ICT-beveiligingsrichtlijnen voor webapplicaties (updated edition, PDF "07-24_0", posted 17-4-2026) | Web application control baseline; OpenCRE mappings to ISO 27002 / NIST SP 800-53 Rev. 5 |
| NCSC-NL Beleids- en beheersingsrichtlijnen voor de ontwikkeling van veilige software | Policy and control layer above the web and mobile guidelines |
| NCSC-NL ICT-beveiligingsrichtlijnen voor TLS (v2.1) | TLS ratings: Good / Sufficient / Phase out |
| BSI TR-02102-1 / -2 (German, widely cited) | Crypto and TLS baselines |

## Disclosure and testing law

- **Leidraad Coordinated Vulnerability Disclosure** (NCSC-NL); DIVD for internet-wide issues.
- Testing law: `testing-law.md` (Art. 138ab Sr, *computervredebreuk*).
