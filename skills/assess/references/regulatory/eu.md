# European Union

Checked 2026-11-18 against eur-lex.europa.eu and digital-strategy.ec.europa.eu. National
implementation (NIS2) differs per member state; for the Netherlands see `nl.md`.

| Instrument | Applies to (role) | What a finding can trigger | Deadline | Authority / channel | Tier · status |
|------------|-------------------|----------------------------|----------|---------------------|---------------|
| **Cyber Resilience Act** — Reg. (EU) 2024/2847, Arts. 13–16, Annex I Parts I–II | `manufacturer` of products with digital elements on the EU market | Actively exploited vulnerability in the client's own product → Art. 14 report; severe incident affecting product security | Early warning ≤24 h · notification ≤72 h · final report ≤14 days after a corrective/mitigating measure is available (severe incident: final report ≤1 month after notification) | ENISA single reporting platform (Art. 16), routed to the CSIRT coordinator | `may_trigger_now` · reporting applies from **11 Sep 2026**; other obligations from **11 Dec 2027** (`readiness` for Annex I conformity until then) |
| **NIS2** — Dir. (EU) 2022/2555 Art. 23 | `essential_entity`, `important_entity` | Significant incident | Early warning ≤24 h · incident notification ≤72 h · final report ≤1 month | National CSIRT / competent authority | `may_trigger_now` where transposed (NL: `nl.md`) |
| **GDPR** — Reg. (EU) 2016/679 Arts. 33–34 | `controller` (processor → notify controller without undue delay) | Personal-data breach | Supervisory authority ≤72 h after awareness (Art. 33); data subjects without undue delay if high risk (Art. 34) | Lead supervisory authority | `may_trigger_now` |
| **AI Act** — Reg. (EU) 2024/1689 Art. 15, amended by Digital Omnibus Reg. (EU) 2026/1744 | Providers/deployers of high-risk AI; GPAI providers | Robustness/cybersecurity gap (poisoning, adversarial examples, confidentiality attacks) in a high-risk system | — | Market-surveillance authority | GPAI: in force since 2 Aug 2025. High-risk: `readiness` (Annex III 2 Dec 2027, Annex I 2 Aug 2028; quote OJ text — open check in `standards.md`) |
| **RED Delegated Reg. (EU) 2022/30** + EN 18031-1/-2/-3:2024 | `manufacturer` of radio equipment | Network-protection (-1), personal-data (-2), financial-transaction (-3) gap → CE non-conformity | — | Market surveillance | In force since **1 Aug 2025** (conformity finding, no reporting clock) |
| **DORA** — Reg. (EU) 2022/2554 Arts. 17–19, 24–27; TLPT RTS Del. Reg. (EU) 2025/1190 | `financial_entity_eu` | Major ICT-related incident (Art. 19); TLPT findings | Per RTS on incident reporting (initial / intermediate / final) — quote the RTS | Competent financial authority | `may_trigger_now` since **17 Jan 2025** |
| **EUCC** — Impl. Reg. (EU) 2024/482 | Vendors seeking EU Common Criteria certification | Certification evidence | — | Certification body | Applicable since **27 Feb 2025** |

## Coordinated vulnerability disclosure

- NIS2 Art. 12: the national CSIRT acts as CVD coordinator; ENISA runs the EU Vulnerability
  Database (EUVD, euvd.enisa.europa.eu).
- CRA Annex I Part II: manufacturers must have a CVD policy and a single point of contact.
- ISO/IEC 29147:2018 and 30111:2019; RFC 9116 `security.txt`.
