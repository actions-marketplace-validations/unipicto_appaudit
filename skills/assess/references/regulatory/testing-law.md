# Legality of testing — check before any active test

Checked 2026-11-20. This table names the laws; it does not replace the client's written
authorization or local legal advice. Apply it to the **tester's location and every target's
location** (`jurisdiction_profile.tester_location`, `hosting_locations`).

| Jurisdiction | Law on unauthorized access / interference | What makes a test lawful in practice | Notes |
|--------------|-------------------------------------------|--------------------------------------|-------|
| Netherlands | Wetboek van Strafrecht Art. 138ab (*computervredebreuk*), 138b, 350a | Written authorization from someone entitled to grant it, within the written scope | NCSC-NL Leidraad CVD for unsolicited findings |
| EU (all member states) | National laws implementing Directive 2013/40/EU on attacks against information systems | Written authorization | Germany: StGB §§ 202a–202c |
| United States | Computer Fraud and Abuse Act, 18 U.S.C. § 1030; state computer-crime laws | Written authorization defining systems, dates, methods | DOJ's 2022 charging policy says good-faith security research should not be charged, but it does not affect civil CFAA liability or state law |
| United Kingdom | Computer Misuse Act 1990 ss. 1–3A | Written authorization | A statutory defence is being added via the National Security Bill and is reported to be narrow (scanning). Do not rely on it |
| Canada | Criminal Code s. 342.1 (unauthorized use of computer), s. 430(1.1) (mischief in relation to computer data) | Written authorization | — |
| Australia | Criminal Code Act 1995 Part 10.7 (ss. 477–478) | Written authorization | — |
| Singapore | Computer Misuse Act 1993 (ss. 3–8) | Written authorization | — |
| Japan | Act on Prohibition of Unauthorized Computer Access (Act No. 128 of 1999); Penal Code Arts. 168-2/168-3, 234-2 | Written authorization from the access administrator | Unsolicited findings: report via the IPA / JPCERT/CC Early Warning Partnership |
| India | Information Technology Act 2000 ss. 43 and 66 | Written authorization | CERT-In 6-hour reporting can apply to the client if testing reveals an incident |
| **China** (warning only) | Criminal Law Arts. 285–286; Cybersecurity Law (amended, in force 1 Jan 2026, broader extraterritorial reach) | **Do not test China-hosted targets** unless `counsel_confirmed` includes `CN`. Data leaving China (including evidence) may be restricted under the Data Security Law and PIPL | Tell the user plainly that this plugin does not assess China-specific obligations beyond these warnings |

## Rules

1. If any target location has no entry here, or the tester's location differs from the target's,
   say so and ask the user to confirm authorization covers it before active tests.
2. Cloud-hosted targets: the hosting region counts as a target location.
3. Evidence storage: if evidence will contain personal data and be stored outside the region it
   came from, note the transfer for counsel (GDPR Chapter V, UK GDPR, PIPL).
