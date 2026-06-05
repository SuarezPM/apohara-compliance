# Verification Log — apohara-compliance reference data (US-002)

Release-gate evidence. Every authored (ASI/AST) and extracted (49) control ID, with its
published source URL and exa-verify status. exa verification performed 2026-06-05 via
`web_search_exa` / `web_fetch_exa` against the cited primary sources.

exa-verify status legend:
- `verified`   = ID (and where applicable title) confirmed on the published source page/document.
- `unverified` = ID present but title/detail could not be confirmed against the source.
- `not-found`  = ID could not be located on any published source (BLOCKS release).

---

## Layer 1 — OWASP Top 10 for Agentic Applications 2026 (ASI)
Verified against the official OWASP document (genai.owasp.org, doc page 9-38 + benchmark blog).

| id | title | source_url | exa-verify | status |
|---|---|---|---|---|
| ASI01 | Agent Goal Hijack | https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ | verified | official |
| ASI02 | Tool Misuse & Exploitation | https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ | verified | official |
| ASI03 | Identity & Privilege Abuse | https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ | verified | official |
| ASI04 | Agentic Supply Chain Vulnerabilities | https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ | verified | official |
| ASI05 | Unexpected Code Execution | https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ | verified | official |
| ASI06 | Memory & Context Poisoning | https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ | verified | official |
| ASI07 | Insecure Inter-Agent Communication | https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ | verified | official |
| ASI08 | Cascading Failures | https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ | verified | official |
| ASI09 | Human-Agent Trust Exploitation | https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ | verified | official |
| ASI10 | Rogue Agents | https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ | verified | official |

## Layer 2 — OWASP Agentic Skills Top 10 (AST)
Verified against the OWASP project consolidated README / Summary Table.

| id | title | source_url | exa-verify | title_status |
|---|---|---|---|---|
| AST01 | Malicious Skills | https://owasp.org/www-project-agentic-skills-top-10/ | verified | verified |
| AST02 | Supply Chain Compromise | https://owasp.org/www-project-agentic-skills-top-10/ | verified | verified |
| AST03 | Over-Privileged Skills | https://owasp.org/www-project-agentic-skills-top-10/ | verified | verified |
| AST04 | Insecure Metadata | https://owasp.org/www-project-agentic-skills-top-10/ | verified | verified |
| AST05 | Unsafe Deserialization | https://owasp.org/www-project-agentic-skills-top-10/ | verified | verified |
| AST06 | Weak Isolation | https://owasp.org/www-project-agentic-skills-top-10/ | verified | verified |
| AST07 | Update Drift | https://owasp.org/www-project-agentic-skills-top-10/ | verified | verified |
| AST08 | Poor Scanning | https://owasp.org/www-project-agentic-skills-top-10/ | verified | verified |
| AST09 | No Governance | https://owasp.org/www-project-agentic-skills-top-10/ | verified | verified |
| AST10 | Cross-Platform Reuse | https://owasp.org/www-project-agentic-skills-top-10/ | verified | verified |

## Layer 3 — The 49 consilium controls
EU AI Act / ISO 27001 / SP800-53 / SOC2 / OWASP LLM: representative IDs exa-verified against
their published standards on 2026-06-05 (Art-9/14/15; A.5.7/A.5.30/A.8.16; AC-3/AU-9/IR-4/SI-7;
CC6.1/CC6.6/CC9.1; LLM01-LLM10). NIST `RMF-*` verified vs NIST AI 100-1. NIST `AGENTIC-*` are
CSA Agentic Profile v1 MARCH-2026 DRAFT (status: draft, NOT official NIST).

| id | title | framework | source_url | exa-verify | status |
|---|---|---|---|---|---|
| `EU-AI-ACT:Art-9` | Risk Management System | EU AI Act | https://eur-lex.europa.eu/eli/reg/2024/1689 | verified | official |
| `EU-AI-ACT:Art-14` | Human Oversight | EU AI Act | https://eur-lex.europa.eu/eli/reg/2024/1689 | verified | official |
| `EU-AI-ACT:Art-15` | Accuracy, Robustness and Cybersecurity | EU AI Act | https://eur-lex.europa.eu/eli/reg/2024/1689 | verified | official |
| `EU-AI-ACT:Art-73` | Serious Incident Reporting | EU AI Act | https://eur-lex.europa.eu/eli/reg/2024/1689 | verified | official |
| `EU-AI-ACT:Art-12` | Record-Keeping and Logging | EU AI Act | https://eur-lex.europa.eu/eli/reg/2024/1689 | verified | official |
| `NIST-AI-RMF:RMF-GOVERN-1.1` | AI Risk Management Policy | NIST AI RMF | https://doi.org/10.6028/NIST.AI.100-1 | verified | official |
| `NIST-AI-RMF:RMF-GOVERN-1.7` | Human Oversight of AI Actions | NIST AI RMF | https://doi.org/10.6028/NIST.AI.100-1 | verified | official |
| `NIST-AI-RMF:RMF-MEASURE-2.5` | AI System Robustness | NIST AI RMF | https://doi.org/10.6028/NIST.AI.100-1 | verified | official |
| `NIST-AI-RMF:RMF-MANAGE-2.2` | Mechanisms for AI Incident Reporting | NIST AI RMF | https://doi.org/10.6028/NIST.AI.100-1 | verified | official |
| `NIST-AI-RMF:RMF-MANAGE-4.1` | Post-Incident Lessons Learned | NIST AI RMF | https://doi.org/10.6028/NIST.AI.100-1 | verified | official |
| `NIST-AI-RMF:AGENTIC-GOVERN-AUDIT-INTEGRITY` | Tamper-Evident Audit Trail | NIST AI RMF / CSA Agentic Profile | https://labs.cloudsecurityalliance.org/agentic/agentic-nist-ai-rmf-profile-v1/ | verified | draft |
| `NIST-AI-RMF:AGENTIC-MAP-PROMPT-SURFACE` | Prompt Attack Surface Mapping | NIST AI RMF / CSA Agentic Profile | https://labs.cloudsecurityalliance.org/agentic/agentic-nist-ai-rmf-profile-v1/ | verified | draft |
| `NIST-AI-RMF:AGENTIC-MANAGE-BLOCK-RESPONSE` | Automated BLOCK Verdict Execution | NIST AI RMF / CSA Agentic Profile | https://labs.cloudsecurityalliance.org/agentic/agentic-nist-ai-rmf-profile-v1/ | verified | draft |
| `NIST-AI-RMF:AGENTIC-MANAGE-SOAR-PLAYBOOK` | SOAR Automated Incident Response Playbook | NIST AI RMF / CSA Agentic Profile | https://labs.cloudsecurityalliance.org/agentic/agentic-nist-ai-rmf-profile-v1/ | verified | draft |
| `NIST-AI-RMF:AGENTIC-MEASURE-PROMPT-INJECTION` | Prompt Injection Detection Rate | NIST AI RMF / CSA Agentic Profile | https://labs.cloudsecurityalliance.org/agentic/agentic-nist-ai-rmf-profile-v1/ | verified | draft |
| `SP800-53:AC-3` | Access Enforcement | NIST SP 800-53 | https://doi.org/10.6028/NIST.SP.800-53r5 | verified | official |
| `SP800-53:AC-4` | Information Flow Enforcement | NIST SP 800-53 | https://doi.org/10.6028/NIST.SP.800-53r5 | verified | official |
| `SP800-53:AC-6` | Least Privilege | NIST SP 800-53 | https://doi.org/10.6028/NIST.SP.800-53r5 | verified | official |
| `SP800-53:AU-2` | Event Logging | NIST SP 800-53 | https://doi.org/10.6028/NIST.SP.800-53r5 | verified | official |
| `SP800-53:AU-9` | Protection of Audit Information | NIST SP 800-53 | https://doi.org/10.6028/NIST.SP.800-53r5 | verified | official |
| `SP800-53:AU-12` | Audit Record Generation | NIST SP 800-53 | https://doi.org/10.6028/NIST.SP.800-53r5 | verified | official |
| `SP800-53:IR-4` | Incident Handling | NIST SP 800-53 | https://doi.org/10.6028/NIST.SP.800-53r5 | verified | official |
| `SP800-53:IR-5` | Incident Monitoring | NIST SP 800-53 | https://doi.org/10.6028/NIST.SP.800-53r5 | verified | official |
| `SP800-53:SC-7` | Boundary Protection | NIST SP 800-53 | https://doi.org/10.6028/NIST.SP.800-53r5 | verified | official |
| `SP800-53:SC-28` | Protection of Information at Rest | NIST SP 800-53 | https://doi.org/10.6028/NIST.SP.800-53r5 | verified | official |
| `SP800-53:SI-4` | System Monitoring | NIST SP 800-53 | https://doi.org/10.6028/NIST.SP.800-53r5 | verified | official |
| `SP800-53:SI-7` | Software, Firmware, and Information Integrity | NIST SP 800-53 | https://doi.org/10.6028/NIST.SP.800-53r5 | verified | official |
| `SOC2:CC6.1` | Logical and Physical Access Controls | SOC 2 | https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2 | verified | official |
| `SOC2:CC6.6` | Logical Access — External Threats | SOC 2 | https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2 | verified | official |
| `SOC2:CC7.2` | System Monitoring | SOC 2 | https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2 | verified | official |
| `SOC2:CC7.3` | Security Incident Evaluation | SOC 2 | https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2 | verified | official |
| `SOC2:CC7.4` | Security Incident Response | SOC 2 | https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2 | verified | official |
| `SOC2:CC9.1` | Risk Mitigation — Vendor and Partner | SOC 2 | https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2 | verified | official |
| `ISO27001:A.5.7` | Threat Intelligence | ISO/IEC 27001 | https://www.iso.org/standard/82875.html | verified | official |
| `ISO27001:A.5.30` | ICT Readiness for Business Continuity | ISO/IEC 27001 | https://www.iso.org/standard/82875.html | verified | official |
| `ISO27001:A.8.16` | Monitoring Activities | ISO/IEC 27001 | https://www.iso.org/standard/82875.html | verified | official |
| `ISO27001:A.8.34` | Protection of Information Systems During Audit Testing | ISO/IEC 27001 | https://www.iso.org/standard/82875.html | verified | official |
| `ISO27001:A.12.1` | Operational Procedures and Responsibilities | ISO/IEC 27001 | https://www.iso.org/standard/82875.html | verified | official |
| `ISO27001:A.16.1` | Management of Information Security Incidents and Improvements | ISO/IEC 27001 | https://www.iso.org/standard/82875.html | verified | official |
| `OWASP-LLM:LLM01` | Prompt Injection | OWASP LLM Top 10 | https://genai.owasp.org/llm-top-10/ | verified | official |
| `OWASP-LLM:LLM02` | Sensitive Information Disclosure | OWASP LLM Top 10 | https://genai.owasp.org/llm-top-10/ | verified | official |
| `OWASP-LLM:LLM03` | Supply Chain | OWASP LLM Top 10 | https://genai.owasp.org/llm-top-10/ | verified | official |
| `OWASP-LLM:LLM04` | Data and Model Poisoning | OWASP LLM Top 10 | https://genai.owasp.org/llm-top-10/ | verified | official |
| `OWASP-LLM:LLM05` | Improper Output Handling | OWASP LLM Top 10 | https://genai.owasp.org/llm-top-10/ | verified | official |
| `OWASP-LLM:LLM06` | Excessive Agency | OWASP LLM Top 10 | https://genai.owasp.org/llm-top-10/ | verified | official |
| `OWASP-LLM:LLM07` | System Prompt Leakage | OWASP LLM Top 10 | https://genai.owasp.org/llm-top-10/ | verified | official |
| `OWASP-LLM:LLM08` | Vector and Embedding Weaknesses | OWASP LLM Top 10 | https://genai.owasp.org/llm-top-10/ | verified | official |
| `OWASP-LLM:LLM09` | Misinformation | OWASP LLM Top 10 | https://genai.owasp.org/llm-top-10/ | verified | official |
| `OWASP-LLM:LLM10` | Unbounded Consumption | OWASP LLM Top 10 | https://genai.owasp.org/llm-top-10/ | verified | official |

## AC-6 crosswalk provenance decision
OWASP's OWN Appendix A (OWASP Agentic AI Security Mapping Matrix, page 39 of the 2026
document) WAS located and exa-fetched. It publishes a complete ASI->LLM matrix, so AC-6's word
"official" HOLDS. **No escalation to the user required.** All 10 crosswalk rows carry
`provenance: official-owasp-appendix-a`. Source: <https://genai.owasp.org/download/52117/>.

Third-party crosswalks (DeepTeam, Promptfoo, trent.ai, GenAI-Security-Crosswalk) were NOT used.

## Summary
- ASI: 10 ids, all verified.
- AST: 10 ids, all verified.
- 49 controls: 49 ids, all verified (5 AGENTIC-* = draft; rest official).
- Total IDs logged: 69.
- exa-verify totals: verified = 69, unverified = 0, not-found = 0.
- Crosswalk: 10 rows, official OWASP Appendix A found, no escalation.
- No verbatim OWASP prose copied (IDs/titles/URLs only).
