# Japan

Checked 2026-11-20. Primary sources: e-gov.go.jp (laws), ppc.go.jp (APPI), cas.go.jp and the
National Cybersecurity Office (NCO), meti.go.jp, ipa.go.jp. Official texts are in Japanese;
quote them, not a translation, in contractual documents.

| Instrument | Applies to (role) | What a finding can trigger | Deadline | Authority / channel | Tier · status |
|------------|-------------------|----------------------------|----------|---------------------|---------------|
| **Act on the Protection of Personal Information (APPI)** Art. 26 + Enforcement Rules Arts. 7–10 | `controller` (business operator handling personal information, including foreign businesses serving people in Japan) | Leakage, loss or damage (or a likelihood of it) involving sensitive data, data that can cause financial damage, an act with a wrongful purpose (e.g. a cyberattack), or **>1,000 individuals** | **Preliminary report promptly** (PPC guidance: about 3–5 days); **final report within 30 days**, or **60 days** where a wrongful purpose may be involved; notify individuals promptly according to the situation | Personal Information Protection Commission (PPC), online form in Japanese | `may_trigger_now` |
| **APPI amendment** (Act No. 56 of 2026, promulgated 17 Jul 2026) | `controller` | Changes to reporting/notification duties; first administrative surcharge for certain serious violations | — | PPC | `readiness` — tougher criminal penalties from **17 Jan 2027**; most provisions by Cabinet Order, **no later than Jul 2028** |
| **Act on the Prevention of Damage from Unauthorized Acts against Important Electronic Computers** (Act No. 42 of 2025, "Active Cyber Defense" / Cyber Response Capability Enhancement Act) | `jp_special_infra_operator` (designated special social infrastructure operators, ~258 operators in 15 sectors) | Specified intrusion event, or an event that could cause one, on a specified important computer | **First report promptly** after becoming aware (published guidance: DDoS as soon as possible; ransomware and other attacks within about 3–5 days); **detailed report within 30 days**. Asset notification of specified important computers by **31 Mar 2027** for existing systems | Sector minister **and** the Prime Minister (via the NCO) | `may_trigger_now` since **1 Oct 2026** (verify the deadlines in the NCO order before contractual use) |
| **Telecommunications Business Act** (accident and incident reporting) | Telecommunications carriers | Serious accidents, communications secrecy breaches | First report promptly; detailed report within 30 days | Ministry of Internal Affairs and Communications (MIC) | `may_trigger_now` |
| **JC-STAR** (IoT product security labelling, METI/IPA) | Consumer and enterprise IoT `manufacturer` (voluntary) | Gaps against STAR-1 baseline (or STAR-3 for network devices and cameras, released 13 Jul 2026) | — | IPA | Voluntary since **25 Mar 2025**; mutual recognition with Singapore CLS (1 Jun 2026) and UK PSTI |

## Testing law and disclosure

- Act on Prohibition of Unauthorized Computer Access (Act No. 128 of 1999) and Penal Code
  Arts. 168-2 / 168-3 (unauthorized electromagnetic records) and 234-2: `testing-law.md`.
- Vulnerability reports: **Information Security Early Warning Partnership** — IPA receives reports,
  JPCERT/CC coordinates with developers (METI notice, aligned with ISO/IEC 29147). The 2026
  guideline revision links this process to the Active Cyber Defense law.
- Two regimes can apply to one ransomware event at a designated operator: the ACD report to the
  minister and Prime Minister, and the APPI report to the PPC. A shared incident report format
  is in preliminary use; confirm with counsel which form satisfies which duty.
