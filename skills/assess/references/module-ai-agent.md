# Module — AI / LLM Features & Agentic Systems

**Standards (verified 2026-11-18 against genai.owasp.org, owasp.org, csrc.nist.gov, eur-lex.europa.eu):**
- **OWASP Top 10 for LLM Applications 2026** (published 4 Aug 2026 per the canonical
  repository; announced 1 Sep 2026; supersedes 2025; version DOI 10.5281/zenodo.22109015):
  LLM01 Prompt Injection · LLM02 Sensitive Information Disclosure · LLM03 Excessive Agency ·
  LLM04 Supply Chain · LLM05 Data and Model Poisoning · LLM06 Unbounded Consumption ·
  LLM07 Misinformation · LLM08 Hidden Context Exposure (formerly System Prompt Leakage) ·
  LLM09 Vector and Embedding Weaknesses · LLM10 Improper Output Handling.
- **OWASP Top 10 for Agentic Applications 2026** (OWASP GenAI Security Project, Agentic Security
  Initiative; released Dec 2025): ASI01 Agent Goal Hijack · ASI02 Tool Misuse and Exploitation ·
  ASI03 Identity and Privilege Abuse · ASI04 Agentic Supply Chain Vulnerabilities ·
  ASI05 Unexpected Code Execution (RCE) · ASI06 Memory and Context Poisoning ·
  ASI07 Insecure Inter-Agent Communication · ASI08 Cascading Failures ·
  ASI09 Human-Agent Trust Exploitation · ASI10 Rogue Agents.
- **OWASP Agentic Skills Top 10 (AST10)** — *incubator* project (repo: "1.0 (2026 Edition)"; no OWASP-published release date) for the
  skill/package layer beneath agent runtime risk; each item mapped to CSA MAESTRO layers:
  AST01 Malicious Skills · AST02 Supply Chain Compromise · AST03 Over-Privileged Skills ·
  AST04 Insecure Metadata · AST05 Untrusted External Instructions · AST06 Weak Isolation ·
  AST07 Update Drift · AST08 Poor Scanning · AST09 No Governance · AST10 Cross-Platform Reuse.
  Use when the target *is* a skill/plugin/MCP package; the full checklist, scanner and rule
  catalogue for that case are in `module-agent-extensions.md`.
- **OWASP AIVSS v0.8** (19 Mar 2026; v1.0 planned end-2026) — *pre-standard*; report alongside
  CVSS v4.0, never instead of it.
- **OWASP GenAI Agent Control Standard (ACS)** (1 Sep 2026, v0.x) — *emerging* runtime-control
  pattern (middleware hooks, separate policy decision point, Agent Bill of Materials); cite as
  a reference pattern, not a conformance requirement.
- **NIST** AI 100-1 (AI RMF), AI 600-1 (Generative AI Profile), AI 100-2 E2025 (adversarial ML
  taxonomy), SP 800-218A; **MITRE ATLAS** (cite version shown on atlas.mitre.org);
  **ISO/IEC 42001:2023**; **MCP Security Best Practices** (modelcontextprotocol.io);
  NCSC/CISA joint guidance "Deploying AI Systems Securely" (Apr 2024) and "AI Data Security" (May 2025);
  OWASP LLM Prompt Injection Prevention Cheat Sheet.
- **EU AI Act** (Reg. (EU) 2024/1689) Art. 15 accuracy, robustness, cybersecurity — see
  `regulatory/eu.md` for the Digital Omnibus dates.

Treat the model as an **untrusted component**: anything it reads can steer it, and anything
it can call is reachable by whoever steers it. Most findings here are architectural and
visible from code, prompts, tool manifests, and skill files — static review goes far.

---

## A. Prompt injection & instruction control — LLM01:2026 · ASI01 · AST05
- [ ] **Direct**: user turns can override system instructions? Test with benign marker instructions ("end your answer with the word PINEAPPLE") rather than harmful ones.
- [ ] **Indirect**: content the model ingests (web pages, documents, emails, tool outputs, RAG chunks, other agents' messages) is treated as data; instructions found there are not followed. Probe with a benign marker embedded in a document you control.
- [ ] Privilege separation between system prompt, developer instructions, and untrusted content (delimiters, structured inputs, separate channels).
- [ ] Output handling (LLM10:2026): model output is not executed, rendered unsafely, or passed to shells/SQL/HTML without validation.

## B. Excessive agency & tool execution — LLM03:2026 · ASI02 · ASI03 · ASI05 · AST03 · AST06
- [ ] Each tool has the **minimum** scope (read-only where possible; narrow filesystem/URL/account scopes).
- [ ] **Confirmation gates** before irreversible or sensitive actions (payments, deletes, sends, deploys, credential use).
- [ ] Agent identity ≠ user identity; the agent cannot escalate to permissions the user lacks; per-action authZ is checked by the tool/backend, not by the prompt.
- [ ] Code execution sandboxed (no network/host access unless required; resource limits; ephemeral).
- [ ] **MCP / plugin / skill servers**: provenance verified, permissions reviewed, tool and skill descriptions treated as untrusted (description injection), no auto-approval of new tools, transport authenticated.
- [ ] Budget/loop limits: max steps, max spend, timeouts (LLM06:2026; ASI08).
- [ ] Runtime control: a policy decision point outside the model approves tool calls (ACS pattern); Agent Bill of Materials lists models, tools, skills, and MCP servers in use.

## C. Data, memory & context integrity — LLM02:2026 · LLM05:2026 · LLM08:2026 · LLM09:2026 · ASI06
- [ ] Hidden context (system prompt, developer instructions, tool configs) contains no secrets; its disclosure would not be a security failure by itself (LLM08:2026 Hidden Context Exposure).
- [ ] RAG/vector store (LLM09:2026): per-user/tenant access control at retrieval time; documents carry ACLs; no cross-tenant leakage via similarity search.
- [ ] Persistent memory: writes validated; untrusted content cannot plant durable instructions; memory can be inspected and purged.
- [ ] PII/secret redaction before logging prompts and completions; retention policy stated.
- [ ] Training/fine-tuning data provenance and poisoning controls where the user trains models.

## D. Multi-agent & human-trust surfaces — ASI07 · ASI09 · ASI10 · ASI01
- [ ] Inter-agent messages authenticated and schema-validated; one compromised agent cannot command others.
- [ ] Agent outputs to humans are labelled as AI-generated where decisions depend on them; high-impact recommendations require human review.
- [ ] Goal/plan integrity: objectives come from the authorized principal, not from ingested content; drift detection and kill switch exist.
- [ ] Observability: full tool-call audit log with inputs/outputs (redacted), retrievable for incident review.

## E. Supply chain for AI components & skills — LLM04:2026 · ASI04 · AST01 · AST02 · AST04 · AST07 · AST08
- [ ] Model weights, adapters, embeddings, prompts, skills, and tool packages come from verified sources with checksums/signatures.
- [ ] Skill/plugin files reviewed before install: no hidden instructions, no network/credential use beyond stated purpose, no self-modifying behaviour.
- [ ] Third-party model APIs: data-handling terms reviewed; no sensitive data sent without authorization.
- [ ] Dependencies scanned as in `module-api-supply-chain.md`.

## F. Misinformation & over-reliance — LLM07:2026 · ASI09
- [ ] Grounding/citations for factual outputs in high-stakes domains; abstention when unsure; user-facing disclaimers where decisions have consequences.

---

## Validation guidance
Use **benign marker payloads** only (unique harmless words, "reply with X", read a canary
file you planted). A successful marker proves the control gap; never demonstrate data
exfiltration with real data or trigger a real sensitive action. Findings in tool manifests,
permission scopes, skill files, and missing confirmation gates are `Confirmed` from code.

## Scoring note
Score with CVSS v4.0 first. Then, as a clearly labelled supplementary figure, apply AIVSS v0.8
(pre-standard): AARS = (10 − CVSS_Base) × (sum of 10 agentic amplification factors, each
0/0.5/1, ÷ 10) × Threat_Multiplier; AIVSS = (CVSS_Base + AARS) × Mitigation_Factor.
Factors cover autonomy, tool reach, memory persistence, multi-agent interaction, and similar. The same injection flaw is a data
leak in a read-only reporting agent and a systemic threat in an agent that can move money.

## Remediation patterns
- Structured prompting with explicit untrusted-content blocks; instruct the model that such blocks are data, and enforce it with output validation.
- Tool allow-lists per task; typed, validated arguments; server-side authZ per call.
- Confirmation UI for irreversible actions; dry-run modes.
- Retrieval-time ACL filtering; tenant-scoped indices.
- Step/spend/time budgets with hard stops and alerting.
- Signed, pinned skills/plugins; review diff on every update.
