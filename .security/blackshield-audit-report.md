# BlackShield Security Audit Report — `google/agentmesh`

- **Scanned Commit:** `1e25dac5c928742a6ef0ca1217054dfd22a95755`
- **Actionable Findings:** `23` (`2 Critical`, `21 High`, `12 Medium`, `7 Low`)
- **BlackShield Platform & Continuous Zero-Cost PR Protection:** [https://blackshield.chaplau.com](https://blackshield.chaplau.com)

## Detailed Findings & Remediation Guide

### 1. [CRITICAL] `BS-AGENT-UC401` — BS-AGENT-UC401: Agent Skill Fetch-and-Execute RCE

- **Category:** `sast`
- **Location:** `agents/skills/agentmesh/SKILL.md:33`
- **Details:** Remote script fetch-and-execute (curl/wget piped to shell) in agent skill at agents/skills/agentmesh/SKILL.md:33
- **Recommended Fix:** Review and remediate vulnerable code pattern.

### 2. [CRITICAL] `BS-AGENT-UC501` — BS-AGENT-UC501: Lethal Trifecta: Credential Read + External Egress

- **Category:** `sast`
- **Location:** `agents/skills/agentmesh/SKILL.md:236`
- **Details:** Lethal Trifecta: local secret/credential harvesting combined with HTTP egress at agents/skills/agentmesh/SKILL.md:236
- **Recommended Fix:** Review and remediate vulnerable code pattern.

### 3. [HIGH] `sec-ai-prompt-interpolation` — sec-ai-prompt-interpolation: Direct User Input Interpolation into LLM Prompt Template

- **Category:** `sast`
- **Location:** `cmd/chaos-agent/agent.py:139`
- **Details:** Interpolating unescaped user variables directly into LLM prompts without delimiter isolation permits prompt injection (AML.T0051). at cmd/chaos-agent/agent.py:139
- **Recommended Fix:** Use parameterized prompt structures, AI Gateway guardrails, or explicit delimiter escaping.

### 4. [HIGH] `sec-xss-raw-html` — sec-xss-raw-html: Cross-Site Scripting (XSS) via Unsanitized HTML

- **Category:** `sast`
- **Location:** `internal/console/public/app.js:333`
- **Details:** Rendering unescaped HTML directly in UI templates exposes web applications to script injection. at internal/console/public/app.js:333
- **Recommended Fix:** Contextually encode output (htmlspecialchars, DOMPurify) and specify an explicit targetOrigin in postMessage.

### 5. [HIGH] `sec-xss-raw-html` — sec-xss-raw-html: Cross-Site Scripting (XSS) via Unsanitized HTML

- **Category:** `sast`
- **Location:** `internal/console/public/app.js:339`
- **Details:** Rendering unescaped HTML directly in UI templates exposes web applications to script injection. at internal/console/public/app.js:339
- **Recommended Fix:** Contextually encode output (htmlspecialchars, DOMPurify) and specify an explicit targetOrigin in postMessage.

### 6. [HIGH] `sec-xss-raw-html` — sec-xss-raw-html: Cross-Site Scripting (XSS) via Unsanitized HTML

- **Category:** `sast`
- **Location:** `internal/console/public/app.js:343`
- **Details:** Rendering unescaped HTML directly in UI templates exposes web applications to script injection. at internal/console/public/app.js:343
- **Recommended Fix:** Contextually encode output (htmlspecialchars, DOMPurify) and specify an explicit targetOrigin in postMessage.

### 7. [HIGH] `sec-xss-raw-html` — sec-xss-raw-html: Cross-Site Scripting (XSS) via Unsanitized HTML

- **Category:** `sast`
- **Location:** `internal/console/public/app.js:389`
- **Details:** Rendering unescaped HTML directly in UI templates exposes web applications to script injection. at internal/console/public/app.js:389
- **Recommended Fix:** Contextually encode output (htmlspecialchars, DOMPurify) and specify an explicit targetOrigin in postMessage.

### 8. [HIGH] `sec-xss-raw-html` — sec-xss-raw-html: Cross-Site Scripting (XSS) via Unsanitized HTML

- **Category:** `sast`
- **Location:** `internal/console/public/app.js:393`
- **Details:** Rendering unescaped HTML directly in UI templates exposes web applications to script injection. at internal/console/public/app.js:393
- **Recommended Fix:** Contextually encode output (htmlspecialchars, DOMPurify) and specify an explicit targetOrigin in postMessage.

### 9. [HIGH] `sec-xss-raw-html` — sec-xss-raw-html: Cross-Site Scripting (XSS) via Unsanitized HTML

- **Category:** `sast`
- **Location:** `internal/console/public/app.js:431`
- **Details:** Rendering unescaped HTML directly in UI templates exposes web applications to script injection. at internal/console/public/app.js:431
- **Recommended Fix:** Contextually encode output (htmlspecialchars, DOMPurify) and specify an explicit targetOrigin in postMessage.

### 10. [HIGH] `sec-xss-raw-html` — sec-xss-raw-html: Cross-Site Scripting (XSS) via Unsanitized HTML

- **Category:** `sast`
- **Location:** `internal/console/public/app.js:469`
- **Details:** Rendering unescaped HTML directly in UI templates exposes web applications to script injection. at internal/console/public/app.js:469
- **Recommended Fix:** Contextually encode output (htmlspecialchars, DOMPurify) and specify an explicit targetOrigin in postMessage.

### 11. [HIGH] `sec-xss-raw-html` — sec-xss-raw-html: Cross-Site Scripting (XSS) via Unsanitized HTML

- **Category:** `sast`
- **Location:** `internal/console/public/app.js:473`
- **Details:** Rendering unescaped HTML directly in UI templates exposes web applications to script injection. at internal/console/public/app.js:473
- **Recommended Fix:** Contextually encode output (htmlspecialchars, DOMPurify) and specify an explicit targetOrigin in postMessage.

### 12. [HIGH] `sec-xss-raw-html` — sec-xss-raw-html: Cross-Site Scripting (XSS) via Unsanitized HTML

- **Category:** `sast`
- **Location:** `internal/console/public/app.js:498`
- **Details:** Rendering unescaped HTML directly in UI templates exposes web applications to script injection. at internal/console/public/app.js:498
- **Recommended Fix:** Contextually encode output (htmlspecialchars, DOMPurify) and specify an explicit targetOrigin in postMessage.

### 13. [HIGH] `sec-xss-raw-html` — sec-xss-raw-html: Cross-Site Scripting (XSS) via Unsanitized HTML

- **Category:** `sast`
- **Location:** `internal/console/public/app.js:502`
- **Details:** Rendering unescaped HTML directly in UI templates exposes web applications to script injection. at internal/console/public/app.js:502
- **Recommended Fix:** Contextually encode output (htmlspecialchars, DOMPurify) and specify an explicit targetOrigin in postMessage.

### 14. [HIGH] `sec-xss-raw-html` — sec-xss-raw-html: Cross-Site Scripting (XSS) via Unsanitized HTML

- **Category:** `sast`
- **Location:** `internal/console/public/app.js:527`
- **Details:** Rendering unescaped HTML directly in UI templates exposes web applications to script injection. at internal/console/public/app.js:527
- **Recommended Fix:** Contextually encode output (htmlspecialchars, DOMPurify) and specify an explicit targetOrigin in postMessage.

### 15. [HIGH] `sec-xss-raw-html` — sec-xss-raw-html: Cross-Site Scripting (XSS) via Unsanitized HTML

- **Category:** `sast`
- **Location:** `internal/console/public/app.js:531`
- **Details:** Rendering unescaped HTML directly in UI templates exposes web applications to script injection. at internal/console/public/app.js:531
- **Recommended Fix:** Contextually encode output (htmlspecialchars, DOMPurify) and specify an explicit targetOrigin in postMessage.

### 16. [HIGH] `sec-xss-raw-html` — sec-xss-raw-html: Cross-Site Scripting (XSS) via Unsanitized HTML

- **Category:** `sast`
- **Location:** `internal/console/public/app.js:725`
- **Details:** Rendering unescaped HTML directly in UI templates exposes web applications to script injection. at internal/console/public/app.js:725
- **Recommended Fix:** Contextually encode output (htmlspecialchars, DOMPurify) and specify an explicit targetOrigin in postMessage.

### 17. [HIGH] `sec-xss-raw-html` — sec-xss-raw-html: Cross-Site Scripting (XSS) via Unsanitized HTML

- **Category:** `sast`
- **Location:** `internal/console/public/app.js:729`
- **Details:** Rendering unescaped HTML directly in UI templates exposes web applications to script injection. at internal/console/public/app.js:729
- **Recommended Fix:** Contextually encode output (htmlspecialchars, DOMPurify) and specify an explicit targetOrigin in postMessage.

### 18. [HIGH] `sec-xss-raw-html` — sec-xss-raw-html: Cross-Site Scripting (XSS) via Unsanitized HTML

- **Category:** `sast`
- **Location:** `internal/console/public/app.js:771`
- **Details:** Rendering unescaped HTML directly in UI templates exposes web applications to script injection. at internal/console/public/app.js:771
- **Recommended Fix:** Contextually encode output (htmlspecialchars, DOMPurify) and specify an explicit targetOrigin in postMessage.

### 19. [HIGH] `sec-xss-raw-html` — sec-xss-raw-html: Cross-Site Scripting (XSS) via Unsanitized HTML

- **Category:** `sast`
- **Location:** `internal/console/public/app.js:775`
- **Details:** Rendering unescaped HTML directly in UI templates exposes web applications to script injection. at internal/console/public/app.js:775
- **Recommended Fix:** Contextually encode output (htmlspecialchars, DOMPurify) and specify an explicit targetOrigin in postMessage.

### 20. [HIGH] `bs-poly-js-ssrf-needle` — bs-poly-js-ssrf-needle: Server-Side Request Forgery (SSRF) via Outbound HTTP Client

- **Category:** `sast`
- **Location:** `internal/console/public/expired-nodes.js:56`
- **Details:** Server-Side Request Forgery (SSRF) via Outbound HTTP Client (CWE-918 / A10:2021). at internal/console/public/expired-nodes.js:56
- **Recommended Fix:** Validate, parameterize, or sanitize untrusted inputs before invoking dangerous sinks.

### 21. [HIGH] `sec-xss-raw-html` — sec-xss-raw-html: Cross-Site Scripting (XSS) via Unsanitized HTML

- **Category:** `sast`
- **Location:** `internal/console/public/expired-nodes.js:72`
- **Details:** Rendering unescaped HTML directly in UI templates exposes web applications to script injection. at internal/console/public/expired-nodes.js:72
- **Recommended Fix:** Contextually encode output (htmlspecialchars, DOMPurify) and specify an explicit targetOrigin in postMessage.

### 22. [HIGH] `sec-xss-raw-html` — sec-xss-raw-html: Cross-Site Scripting (XSS) via Unsanitized HTML

- **Category:** `sast`
- **Location:** `internal/console/public/expired-nodes.js:140`
- **Details:** Rendering unescaped HTML directly in UI templates exposes web applications to script injection. at internal/console/public/expired-nodes.js:140
- **Recommended Fix:** Contextually encode output (htmlspecialchars, DOMPurify) and specify an explicit targetOrigin in postMessage.

### 23. [HIGH] `CVE-2024-26130` — CVE-2024-26130 in cryptography@42

- **Category:** `vulnerability`
- **Location:** `sdk/python/pyproject.toml`
- **Affected Package:** `cryptography@42`
- **Details:** NULL pointer dereference in pkcs12.serialize_key_and_certificates in Python cryptography.
- **Recommended Fix:** Upgrade `cryptography` to `42.0.4` or newer

