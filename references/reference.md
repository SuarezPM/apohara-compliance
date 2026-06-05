# apohara-compliance — Reference Data

Human-readable reference generated from the machine-readable YAML in this directory.
Source of truth = the `*.yaml` files; regenerate this file from them, do not edit by hand.

All framework IDs, titles, versions, and URLs are facts cited from their published
sources. No copyrighted descriptive prose (e.g. OWASP CC BY-SA text) is reproduced.

**This is guidance/mapping data, NOT a certification or legal advice.**

Generated: 2026-06-05

---

## 1. OWASP Top 10 for Agentic Applications (2026) — ASI
Source: <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/> · document <https://genai.owasp.org/download/52117/> · version `2026` · status `official`

| ID | Title | Version | Status |
|---|---|---|---|
| ASI01 | Agent Goal Hijack | 2026 | official |
| ASI02 | Tool Misuse & Exploitation | 2026 | official |
| ASI03 | Identity & Privilege Abuse | 2026 | official |
| ASI04 | Agentic Supply Chain Vulnerabilities | 2026 | official |
| ASI05 | Unexpected Code Execution | 2026 | official |
| ASI06 | Memory & Context Poisoning | 2026 | official |
| ASI07 | Insecure Inter-Agent Communication | 2026 | official |
| ASI08 | Cascading Failures | 2026 | official |
| ASI09 | Human-Agent Trust Exploitation | 2026 | official |
| ASI10 | Rogue Agents | 2026 | official |

## 2. OWASP Agentic Skills Top 10 — AST
Source: <https://owasp.org/www-project-agentic-skills-top-10/> · status `draft` (OWASP New Project Proposal). Usable to self-audit this very skill (AST01-AST05 apply to apohara-compliance's own distribution surface).

| ID | Title | Title status |
|---|---|---|
| AST01 | Malicious Skills | verified |
| AST02 | Supply Chain Compromise | verified |
| AST03 | Over-Privileged Skills | verified |
| AST04 | Insecure Metadata | verified |
| AST05 | Unsafe Deserialization | verified |
| AST06 | Weak Isolation | verified |
| AST07 | Update Drift | verified |
| AST08 | Poor Scanning | verified |
| AST09 | No Governance | verified |
| AST10 | Cross-Platform Reuse | verified |

## 3. The 49 consilium controls
Extracted from `compliance-suite.md`. The 5 NIST `AGENTIC-*` rows are CSA Agentic
Profile v1 (March 2026 DRAFT, not official NIST). OWASP LLM authoritative version = 2025.

| ID | Title | Framework | Version | Status | consilium_ref |
|---|---|---|---|---|---|
| `EU-AI-ACT:Art-9` | Risk Management System | EU AI Act | Regulation (EU) 2024/1689 | official | compliance-suite.md:51 |
| `EU-AI-ACT:Art-14` | Human Oversight | EU AI Act | Regulation (EU) 2024/1689 | official | compliance-suite.md:52 |
| `EU-AI-ACT:Art-15` | Accuracy, Robustness and Cybersecurity | EU AI Act | Regulation (EU) 2024/1689 | official | compliance-suite.md:53 |
| `EU-AI-ACT:Art-73` | Serious Incident Reporting | EU AI Act | Regulation (EU) 2024/1689 | official | compliance-suite.md:54 |
| `EU-AI-ACT:Art-12` | Record-Keeping and Logging | EU AI Act | Regulation (EU) 2024/1689 | official | compliance-suite.md:55 |
| `NIST-AI-RMF:RMF-GOVERN-1.1` | AI Risk Management Policy | NIST AI RMF | 1.0 | official | compliance-suite.md:79 |
| `NIST-AI-RMF:RMF-GOVERN-1.7` | Human Oversight of AI Actions | NIST AI RMF | 1.0 | official | compliance-suite.md:80 |
| `NIST-AI-RMF:RMF-MEASURE-2.5` | AI System Robustness | NIST AI RMF | 1.0 | official | compliance-suite.md:81 |
| `NIST-AI-RMF:RMF-MANAGE-2.2` | Mechanisms for AI Incident Reporting | NIST AI RMF | 1.0 | official | compliance-suite.md:82 |
| `NIST-AI-RMF:RMF-MANAGE-4.1` | Post-Incident Lessons Learned | NIST AI RMF | 1.0 | official | compliance-suite.md:83 |
| `NIST-AI-RMF:AGENTIC-GOVERN-AUDIT-INTEGRITY` | Tamper-Evident Audit Trail | NIST AI RMF / CSA Agentic Profile | CSA Agentic Profile v1 (March 2026 DRAFT) | draft | compliance-suite.md:84 |
| `NIST-AI-RMF:AGENTIC-MAP-PROMPT-SURFACE` | Prompt Attack Surface Mapping | NIST AI RMF / CSA Agentic Profile | CSA Agentic Profile v1 (March 2026 DRAFT) | draft | compliance-suite.md:85 |
| `NIST-AI-RMF:AGENTIC-MANAGE-BLOCK-RESPONSE` | Automated BLOCK Verdict Execution | NIST AI RMF / CSA Agentic Profile | CSA Agentic Profile v1 (March 2026 DRAFT) | draft | compliance-suite.md:86 |
| `NIST-AI-RMF:AGENTIC-MANAGE-SOAR-PLAYBOOK` | SOAR Automated Incident Response Playbook | NIST AI RMF / CSA Agentic Profile | CSA Agentic Profile v1 (March 2026 DRAFT) | draft | compliance-suite.md:87 |
| `NIST-AI-RMF:AGENTIC-MEASURE-PROMPT-INJECTION` | Prompt Injection Detection Rate | NIST AI RMF / CSA Agentic Profile | CSA Agentic Profile v1 (March 2026 DRAFT) | draft | compliance-suite.md:88 |
| `SP800-53:AC-3` | Access Enforcement | NIST SP 800-53 | Rev 5 | official | compliance-suite.md:101 |
| `SP800-53:AC-4` | Information Flow Enforcement | NIST SP 800-53 | Rev 5 | official | compliance-suite.md:102 |
| `SP800-53:AC-6` | Least Privilege | NIST SP 800-53 | Rev 5 | official | compliance-suite.md:103 |
| `SP800-53:AU-2` | Event Logging | NIST SP 800-53 | Rev 5 | official | compliance-suite.md:104 |
| `SP800-53:AU-9` | Protection of Audit Information | NIST SP 800-53 | Rev 5 | official | compliance-suite.md:105 |
| `SP800-53:AU-12` | Audit Record Generation | NIST SP 800-53 | Rev 5 | official | compliance-suite.md:106 |
| `SP800-53:IR-4` | Incident Handling | NIST SP 800-53 | Rev 5 | official | compliance-suite.md:107 |
| `SP800-53:IR-5` | Incident Monitoring | NIST SP 800-53 | Rev 5 | official | compliance-suite.md:108 |
| `SP800-53:SC-7` | Boundary Protection | NIST SP 800-53 | Rev 5 | official | compliance-suite.md:109 |
| `SP800-53:SC-28` | Protection of Information at Rest | NIST SP 800-53 | Rev 5 | official | compliance-suite.md:110 |
| `SP800-53:SI-4` | System Monitoring | NIST SP 800-53 | Rev 5 | official | compliance-suite.md:111 |
| `SP800-53:SI-7` | Software, Firmware, and Information Integrity | NIST SP 800-53 | Rev 5 | official | compliance-suite.md:112 |
| `SOC2:CC6.1` | Logical and Physical Access Controls | SOC 2 | AICPA TSC 2017 | official | compliance-suite.md:125 |
| `SOC2:CC6.6` | Logical Access — External Threats | SOC 2 | AICPA TSC 2017 | official | compliance-suite.md:126 |
| `SOC2:CC7.2` | System Monitoring | SOC 2 | AICPA TSC 2017 | official | compliance-suite.md:127 |
| `SOC2:CC7.3` | Security Incident Evaluation | SOC 2 | AICPA TSC 2017 | official | compliance-suite.md:128 |
| `SOC2:CC7.4` | Security Incident Response | SOC 2 | AICPA TSC 2017 | official | compliance-suite.md:129 |
| `SOC2:CC9.1` | Risk Mitigation — Vendor and Partner | SOC 2 | AICPA TSC 2017 | official | compliance-suite.md:130 |
| `ISO27001:A.5.7` | Threat Intelligence | ISO/IEC 27001 | 2022 | official | compliance-suite.md:142 |
| `ISO27001:A.5.30` | ICT Readiness for Business Continuity | ISO/IEC 27001 | 2022 | official | compliance-suite.md:143 |
| `ISO27001:A.8.16` | Monitoring Activities | ISO/IEC 27001 | 2022 | official | compliance-suite.md:144 |
| `ISO27001:A.8.34` | Protection of Information Systems During Audit Testing | ISO/IEC 27001 | 2022 | official | compliance-suite.md:145 |
| `ISO27001:A.12.1` | Operational Procedures and Responsibilities | ISO/IEC 27001 | 2022 | official | compliance-suite.md:146 |
| `ISO27001:A.16.1` | Management of Information Security Incidents and Improvements | ISO/IEC 27001 | 2022 | official | compliance-suite.md:147 |
| `OWASP-LLM:LLM01` | Prompt Injection | OWASP LLM Top 10 | 2025 | official | compliance-suite.md:161 |
| `OWASP-LLM:LLM02` | Sensitive Information Disclosure | OWASP LLM Top 10 | 2025 | official | compliance-suite.md:162 |
| `OWASP-LLM:LLM03` | Supply Chain | OWASP LLM Top 10 | 2025 | official | compliance-suite.md:163 |
| `OWASP-LLM:LLM04` | Data and Model Poisoning | OWASP LLM Top 10 | 2025 | official | compliance-suite.md:164 |
| `OWASP-LLM:LLM05` | Improper Output Handling | OWASP LLM Top 10 | 2025 | official | compliance-suite.md:165 |
| `OWASP-LLM:LLM06` | Excessive Agency | OWASP LLM Top 10 | 2025 | official | compliance-suite.md:166 |
| `OWASP-LLM:LLM07` | System Prompt Leakage | OWASP LLM Top 10 | 2025 | official | compliance-suite.md:167 |
| `OWASP-LLM:LLM08` | Vector and Embedding Weaknesses | OWASP LLM Top 10 | 2025 | official | compliance-suite.md:168 |
| `OWASP-LLM:LLM09` | Misinformation | OWASP LLM Top 10 | 2025 | official | compliance-suite.md:169 |
| `OWASP-LLM:LLM10` | Unbounded Consumption | OWASP LLM Top 10 | 2025 | official | compliance-suite.md:170 |

## 4. ASI -> LLM crosswalk (OWASP Appendix A)
Canonical source: OWASP Top 10 for Agentic Applications 2026 — Appendix A (OWASP Agentic AI Security Mapping Matrix) (page 39), document <https://genai.owasp.org/download/52117/>.
Provenance: `official-owasp-appendix-a` · LLM framework version `2025`.

| ASI | ASI Title | Mapped LLM IDs | Mapped LLM Titles |
|---|---|---|---|
| ASI01 | Agent Goal Hijack | LLM01:2025, LLM06:2025 | Prompt Injection, Excessive Agency |
| ASI02 | Tool Misuse & Exploitation | LLM06:2025 | Excessive Agency |
| ASI03 | Identity & Privilege Abuse | LLM01:2025, LLM06:2025, LLM02:2025 | Prompt Injection, Excessive Agency, Sensitive Information Disclosure |
| ASI04 | Agentic Supply Chain Vulnerabilities | LLM03:2025 | Supply Chain |
| ASI05 | Unexpected Code Execution | LLM01:2025, LLM05:2025 | Prompt Injection, Improper Output Handling |
| ASI06 | Memory & Context Poisoning | LLM01:2025, LLM04:2025, LLM08:2025 | Prompt Injection, Data and Model Poisoning, Vector and Embedding Weaknesses |
| ASI07 | Insecure Inter-Agent Communication | LLM02:2025, LLM06:2025 | Sensitive Information Disclosure, Excessive Agency |
| ASI08 | Cascading Failures | LLM01:2025, LLM04:2025, LLM06:2025 | Prompt Injection, Data and Model Poisoning, Excessive Agency |
| ASI09 | Human-Agent Trust Exploitation | LLM01:2025, LLM05:2025, LLM06:2025, LLM09:2025 | Prompt Injection, Improper Output Handling, Excessive Agency, Misinformation |
| ASI10 | Rogue Agents | LLM02:2025, LLM09:2025 | Sensitive Information Disclosure, Misinformation |

## 5. Detection rules — 16 AGT-* incident codes
Extracted from `incident-taxonomy.md`. Signals are real detection-signal keywords from the source.

| AGT code | Name | Sev | ASI xref | Maps to controls | Confidence | Citation |
|---|---|---|---|---|---|---|
| AGT-PI-001 | Prompt Override Attempt | 8 | ASI01 | NIST-AI-RMF:RMF-GOVERN-1.1, OWASP-LLM:LLM01, EU-AI-ACT:Art-14, SP800-53:SI-4 | 0.8 | incident-taxonomy.md:52 |
| AGT-PI-002 | Roleplay Persona Manipulation | 7 | ASI01 | OWASP-LLM:LLM01, NIST-AI-RMF:AGENTIC-MAP-PROMPT-SURFACE, EU-AI-ACT:Art-9 | 0.7 | incident-taxonomy.md:53 |
| AGT-PI-003 | Indirect Prompt Injection | 9 | ASI01, ASI06 | OWASP-LLM:LLM05, SP800-53:SI-7, EU-AI-ACT:Art-14, ISO27001:A.12.1 | 0.9 | incident-taxonomy.md:54 |
| AGT-EXF-001 | Database Dump Request | 9 | ASI02, ASI03 | SP800-53:AC-3, SOC2:CC6.1, GDPR:Art-32, OWASP-LLM:LLM02 | 0.9 | incident-taxonomy.md:66 |
| AGT-EXF-002 | Unauthorized Outbound Network Call | 9 | ASI02, ASI04 | SP800-53:SC-7, SOC2:CC6.6, ISO27001:A.8.16, OWASP-LLM:LLM02 | 0.9 | incident-taxonomy.md:67 |
| AGT-EXF-003 | PII Aggregation Attack | 8 | ASI03 | SP800-53:AC-4, GDPR:Art-5, OWASP-LLM:LLM02, CCPA:1798.100 | 0.8 | incident-taxonomy.md:68 |
| AGT-MIS-001 | Destructive Tool Invocation | 10 | ASI02, ASI05 | SP800-53:SI-7, EU-AI-ACT:Art-9, ISO27001:A.12.1 | 0.9 | incident-taxonomy.md:80 |
| AGT-MIS-002 | Privilege Escalation Attempt | 10 | ASI03 | SP800-53:AC-6, SOC2:CC6.1, EU-AI-ACT:Art-14 | 0.9 | incident-taxonomy.md:81 |
| AGT-MIS-003 | Unauthorized Transaction | 8 | ASI02 | NIST-AI-RMF:RMF-GOVERN-1.7, EU-AI-ACT:Art-14, SOC2:CC9.1, ISO27001:A.16.1 | 0.8 | incident-taxonomy.md:82 |
| AGT-FIN-001 | High-Value Financial Transfer | 10 | ASI02 | PCI-DSS:v4-10.7, NIST-AI-RMF:RMF-GOVERN-1.7, SOC2:CC9.1, EU-AI-ACT:Art-9 | 0.9 | incident-taxonomy.md:94 |
| AGT-FIN-002 | Financial Fraud Pattern | 9 | ASI02 | PCI-DSS:v4-10.6, SP800-53:AU-2, SOC2:CC7.2, FinCEN:31-CFR-1020 | 0.9 | incident-taxonomy.md:95 |
| AGT-PII-001 | PII Leakage | 8 | ASI03 | GDPR:Art-5, CCPA:1798.100, HIPAA:164.514, OWASP-LLM:LLM02 | 0.8 | incident-taxonomy.md:107 |
| AGT-PII-002 | PII Re-identification / Linkage Attack | 9 | ASI03 | GDPR:Recital-26, CCPA:1798.140, ISO27001:A.5.7 | 0.9 | incident-taxonomy.md:108 |
| AGT-GOV-001 | Policy Bypass | 8 | ASI01, ASI10 | NIST-AI-RMF:RMF-GOVERN-1.1, SOC2:CC7.3, EU-AI-ACT:Art-9 | 0.8 | incident-taxonomy.md:120 |
| AGT-GOV-002 | Audit Log Tampering | 10 | ASI10 | SP800-53:AU-9, SOC2:CC7.3, ISO27001:A.8.16, EU-AI-ACT:Art-12 | 0.9 | incident-taxonomy.md:121 |
| AGT-GOV-003 | Human Oversight Bypass | 10 | ASI09, ASI10 | EU-AI-ACT:Art-14, NIST-AI-RMF:RMF-GOVERN-1.7, SOC2:CC9.1 | 0.9 | incident-taxonomy.md:122 |

---

### Sources
- OWASP Top 10 for Agentic Applications 2026: <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>
- OWASP Agentic Skills Top 10: <https://owasp.org/www-project-agentic-skills-top-10/>
- OWASP Top 10 for LLM Applications 2025: <https://genai.owasp.org/llm-top-10/>
- EU AI Act (Regulation (EU) 2024/1689): <https://eur-lex.europa.eu/eli/reg/2024/1689>
- NIST AI RMF 1.0: <https://doi.org/10.6028/NIST.AI.100-1>
- CSA Agentic Profile v1 (March 2026 DRAFT): <https://labs.cloudsecurityalliance.org/agentic/agentic-nist-ai-rmf-profile-v1/>
- NIST SP 800-53 Rev 5: <https://doi.org/10.6028/NIST.SP.800-53r5>
- SOC 2 AICPA TSC 2017: <https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2>
- ISO/IEC 27001:2022: <https://www.iso.org/standard/82875.html>
- Consilium source docs: `compliance-suite.md`, `incident-taxonomy.md`, `nist-mapping.md`
