# Module — Mobile Apps & Smart-Device Companion Apps (iOS / Android / IoT)

**Standards:** OWASP MASVS v2.1.0 (8 control groups / 24 controls), OWASP MASTG v2.0.0
(June 2026; traceability MASVS control → MASWE weakness → MASTG test → demo), OWASP MASWE
v1.0.0. EU market access for radio devices: RED Delegated Regulation (EU) 2022/30 +
EN 18031-1/-2/-3 (mandatory since 1 Aug 2025); CRA Annex I from 11 Dec 2027 (see
`regulatory/eu.md`). For the device firmware itself see `module-hardware-firmware.md`.

Most of this module is **static** (decompiled APK/IPA, manifests, config, source) and
can run without any live device. Dynamic checks need a test device the user controls.

---

## MASVS-STORAGE — data at rest
- [ ] No credentials, tokens, or PII in plain SQLite/Realm, SharedPreferences/NSUserDefaults, files, or logs.
- [ ] Sensitive data in Keychain (iOS) / Android Keystore (StrongBox where available) backed storage.
- [ ] Backup exclusion for sensitive stores (`allowBackup=false` or targeted exclusion; on Android 12+ also `dataExtractionRules`; iOS `isExcludedFromBackup`).
- [ ] Clipboard, screenshots (`FLAG_SECURE` / blur on background), and keyboard caches considered for sensitive screens.

## MASVS-CRYPTO
- [ ] No ECB, DES/3DES, RC4, MD5/SHA-1 for security purposes; AES-GCM/ChaCha20-Poly1305, RSA ≥ 2048 / ECC P-256+.
- [ ] Keys from platform keystores or proper KDFs; no hardcoded keys/IVs; IV/nonce unique per message.
- [ ] Secure RNG (`SecureRandom`, `SecRandomCopyBytes`), not `Math.random`/`rand()`.

## MASVS-AUTH
- [ ] Server-side session/token lifecycle; local "auth" only gates UI, never data.
- [ ] Biometric/keyguard binding uses keystore-backed keys (not a boolean callback).
- [ ] Token revocation on logout and device change; step-up auth for sensitive actions.

## MASVS-NETWORK
- [ ] TLS everywhere; cleartext disabled (Network Security Config — cleartext is off by default from API 28; `usesCleartextTraffic` not re-enabled; iOS ATS not globally disabled).
- [ ] Hostname verification and chain validation not overridden (watch for `TrustManager`/`SecTrustEvaluate` bypasses "for debugging").
- [ ] Certificate pinning is **not required by default**: Android documentation advises against it unless you control server-certificate rotation; Apple supports declarative pinning via ATS `NSPinnedDomains`. Where the threat model requires it, verify a pin-set with backup pins and a rotation plan. Report absence of pinning as Informational unless the threat model says otherwise.

## MASVS-PLATFORM
- [ ] Exported activities/services/receivers/providers minimized and permission-protected; `android:exported` declared explicitly (required for components with intent filters when targeting API 31+); intent filters validated.
- [ ] Deep links / App Links / Universal Links verified (asset links / AASA) and input-validated.
- [ ] WebView: JavaScript only where needed, `addJavascriptInterface` restricted, file/content access off, URL allow-list.
- [ ] Permissions minimal and runtime-requested with justification; no dangerous permissions unused.
- [ ] IPC payloads treated as untrusted input.

## MASVS-CODE
- [ ] Target SDK / minimum OS current; dependencies scanned (see `module-api-supply-chain.md`).
- [ ] Debuggable flag off in release; logging stripped of sensitive data; no leftover test endpoints.

## MASVS-RESILIENCE (defence in depth, not a primary control)
- [ ] Obfuscation/minification of release builds; integrity checks; root/jailbreak and debugger detection *as signals*, with graceful handling.
- [ ] Do not rate an app Critical solely for missing resilience controls; rate by what the controls would have protected.

## MASVS-PRIVACY
- [ ] Data collection matches store declarations and privacy policy; third-party SDK data flows inventoried.
- [ ] Identifiers (advertising ID, device IDs) used only with purpose and consent.

---

## Smart-device protocols (companion-app side)
- [ ] **BLE**: pairing mode (avoid Just Works for sensitive characteristics), encryption/authentication on characteristics, no static passkeys, replay protection, GATT write permissions.
- [ ] **MQTT**: TLS, per-device credentials/certs, topic ACLs (no wildcard subscribe/publish), no anonymous broker access, retained-message exposure.
- [ ] **Local/LAN control**: authenticated commands, no cleartext control ports, mDNS/UPnP exposure reviewed.
- [ ] **Cloud gateway**: device identity bound to account; command authorization checked server-side (a classic BOLA surface).

---

## Validation guidance
Static evidence (manifest flag, decompiled call, config value) is usually `Confirmed`
for configuration findings. Runtime behaviour (pinning bypass, IPC exploitation) is
`Confirmed` only when exercised on a device you control; otherwise `Likely`.

## Remediation patterns
- Move secrets to Keychain/Keystore; delete from prefs on upgrade path.
- Replace custom `TrustManager`/ATS exceptions with platform defaults + network security config.
- Set `android:exported="false"` unless externally required; add signature-level permissions for shared components.
