# Module — Embedded Hardware & Firmware

**Standards & references:**
- OWASP ISVS 1.0 (V1 IoT Ecosystem, V2 User Space Application, V3 Software Platform,
  V4 Communication, V5 Hardware Platform); OWASP IoT Top 10 (2018, latest); OWASP FSTM and
  OWASP ISTG (cite version from the project page at time of use).
- ETSI EN 303 645 V3.1.3 (2024-09); conformance assessment ETSI TS 103 701 V2.1.1 (2025-05), aligned to EN 303 645 V3.1.3 (supersedes V1.1.1, 2021).
- NIST IR 8259 Rev. 1 (final 20 Apr 2026) + IR 8259A (May 2020) / 8259B (Aug 2021);
  SP 800-213 (2021, final; Rev. 1 is a draft, Jun 2026); SP 800-193 (platform firmware
  resiliency); SP 800-147/147B (BIOS protection).
- EU: RED Delegated Regulation (EU) 2022/30 + **EN 18031-1/-2/-3:2024** (mandatory for
  radio equipment since 1 Aug 2025; OJ reference with restrictions, Implementing Decision
  (EU) 2025/138); Cyber Resilience Act (Reg. (EU) 2024/2847: Art. 14 reporting from
  11 Sep 2026, other obligations from 11 Dec 2027); EUCC (Reg. (EU) 2024/482, applicable
  27 Feb 2025).
- Certification context: PSA Certified, SESIP (EN 17927), IEC 62443-4-2 (industrial).
- CWE hardware view (CWE-1194).

This module is primarily **firmware-image and design review**. Live electrical/RF
probing requires physical access to a device the user owns and user-run tooling; treat
it as advisory guidance for the user's own lab, with the same scope and non-destructive
rules as everything else (no bricking, no fuse-blowing, no irreversible writes).

---

## A. Firmware image analysis (static)

- [ ] Obtain the image legitimately (vendor download, device the user owns). Identify format, compression, filesystem; extract read-only.
- [ ] **Secrets in image**: private keys, API tokens, cloud credentials, Wi-Fi/MQTT creds, hardcoded passwords in `/etc/shadow`-style files or init scripts. Redact in report.
- [ ] **Component inventory** → SBOM: kernel, libc, OpenSSL/mbedTLS, BusyBox, web server, MQTT client. Run `scripts/vuln_intel.py` on the CVEs found (see `module-api-supply-chain.md`).
- [ ] **Services on boot**: telnet/SSH/HTTP/UPnP enabled by default? Default or empty credentials? Debug daemons left in?
- [ ] **Binary hardening**: NX, PIE, RELRO, stack canaries, stripped symbols — report as hardening gaps, not vulnerabilities.
- [ ] **Update mechanism**: signed images (which algorithm, where is the public key, is it rotatable?), TLS for download, anti-rollback, integrity check before flash, fail-safe (A/B) partitions.
- [ ] **Configuration & logs**: cleartext config with secrets; verbose logs shipped to cloud with PII.

## B. Secure boot & root of trust

- [ ] Boot chain verified from immutable ROM/OTP through bootloader to kernel/app; no unsigned-stage gaps.
- [ ] Debug/unlock states and bootloader console disabled or authenticated in production.
- [ ] Keys in secure element / TPM / TrustZone where the SoC offers it; no key material in plain flash.
- [ ] Rollback protection and revocation of compromised signing keys possible.

## C. Debug & physical interfaces

- [ ] **UART/serial**: console present in production? Authenticated? Root shell on boot?
- [ ] **JTAG/SWD**: disabled, fused off, or password-protected in production units.
- [ ] **Flash/EEPROM**: readable in-circuit? Encrypted at rest? Does extraction yield secrets?
- [ ] **Test pads / hidden headers** documented and disabled.

Guidance for live checks the user may run on their own device: identify interfaces
non-invasively first (datasheets, visual inspection, multimeter continuity), confirm
whether they are enabled, and stop at **demonstrating** access exists — do not modify
flash, blow fuses, or alter boot state.

## D. Radio & local communications

- [ ] BLE / Zigbee / Z-Wave / Thread / LoRa / Wi-Fi: pairing/commissioning security, encryption on by default, key provisioning not static across fleet, replay protection. (App-side detail in `module-mobile-smart-device.md`.)
- [ ] Cleartext local protocols (HTTP control, Telnet, MQTT without TLS) flagged.
- [ ] Device identity: per-device certificates/keys, not fleet-wide shared secrets.

## E. Side-channel & fault-injection awareness (advisory)

Report **exposure** (e.g., unprotected crypto on a general MCU handling long-lived keys,
no glitch detection on a secure-boot path) and recommend mitigations. Do not develop or
document attack procedures; refer the user to vendor hardening guides and certified labs
for formal evaluation (e.g., Common Criteria, SESIP, PSA Certified).

## F. Lifecycle & compliance mapping

- [ ] Vulnerability disclosure policy and update support period declared (ETSI EN 303 645 §5.2–5.3, CRA Annex I).
- [ ] CRA Art. 14 reporting readiness (applies from 11 Sep 2026): actively exploited vulnerability → early warning ≤24 h, notification ≤72 h, final report ≤14 days after a corrective/mitigating measure is available; severe incident → final report ≤1 month after the notification; all via the ENISA single reporting platform (Art. 16).
- [ ] No universal default passwords (ETSI EN 303 645 §5.1).
- [ ] Sensitive security parameters stored securely (§5.4); communicate securely (§5.5); minimize exposed attack surface (§5.6).
- [ ] Secure update and software integrity (§5.3, §5.7).
- [ ] Personal data secure (§5.8); telemetry examined for security anomalies (§5.10); telemetry data minimisation and transparency (clause 6, provisions 6-4, 6-5).
- [ ] User data erasable in a simple manner / factory reset wipes credentials and user data (§5.11, provision 5.11-1).
- [ ] Resilience to outages (§5.9); input data validated (§5.13).
- [ ] RED DA / EN 18031 applicability checked for radio products sold in the EU (-1 network protection, -2 personal data, -3 financial transactions).

---

## Validation guidance
Image-derived evidence (a key file, a `telnetd` in init, an unsigned update path in
code) is `Confirmed` for the image examined; note firmware version. Behaviour on
hardware is `Confirmed` only when the user observes it on their own unit; otherwise
`Likely`.

## Remediation patterns
- Move credentials to per-device provisioning at manufacture; rotate fleet-wide secrets found in images.
- Enforce signed, TLS-delivered, anti-rollback updates with A/B partitions.
- Fuse off JTAG/SWD and disable UART console (or require authenticated enable) for production SKUs.
- Replace Telnet/HTTP control with SSH/HTTPS or mutually-authenticated channels; disable unused services.
