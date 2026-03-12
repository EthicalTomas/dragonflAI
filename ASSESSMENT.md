# dragonflAI — Bug Bounty Hunting AI Assessment

## Overall Rating: **6.5 / 10**

dragonflAI has an impressively solid foundation — scope enforcement, multi-tool recon pipeline, heuristic detection, human-in-the-loop workflow, and a well-structured FastAPI + Streamlit architecture. However, the LLM integration that makes it an *AI* platform is currently a no-op (NullProvider), and several critical recon capabilities found in real-world workflows are missing.

---

## What Works Well ✅

| Area | Assessment |
|------|-----------|
| **Architecture** | Clean separation of concerns; FastAPI + RQ + SQLAlchemy + Streamlit is production-ready |
| **Scope enforcement** | Default-deny with domain/wildcard/CIDR validation is correct and safe |
| **Heuristic detection** | ~20 signal checks across parameters, paths, headers — good starting coverage |
| **Verification system** | Open redirect, reflected XSS, takeover, screenshot — reduces false positives well |
| **CVSS 3.1 scoring** | Full base score calculator with correct formulas |
| **Human review workflow** | DRAFT → NEEDS_REVIEW → READY_TO_SUBMIT prevents accidental disclosure |
| **Nuclei integration** | Template pinning, tag allowlist/denylist, scope filtering — responsibly implemented |
| **Report generation** | Three templates (full, platform, summary) with LLM enhancement hook |
| **Import support** | Burp Suite XML and OWASP ZAP JSON/XML parsers |
| **Security hygiene** | Secret redaction, response size limits, audit logging |

---

## Gaps and Lacking Areas 🔴

### 1. LLM Integration Is Non-Functional (Critical)
**Rating impact: −1.5 pts**

The platform's "AI" identity is currently provided by a `NullLLMProvider` that returns a static string. There are no working LLM provider implementations.

- **Missing:** Ollama provider (local, free), OpenAI provider, Anthropic provider
- **Impact:** Report enhancement, remediation suggestions, and all planned RAG/chat features are completely disabled
- **Fix:** Implement concrete `LLMProvider` subclasses — see `backend/app/llm/`

### 2. Missing Critical Recon Tools (High)
**Rating impact: −1.0 pt**

Real-world bug bounty workflows depend on tools that are absent:

| Missing Tool | Purpose | Impact |
|---|---|---|
| **Katana** | Web crawling & JS endpoint extraction | Finds hidden API endpoints, SPAs |
| **GAU / Waybackurls** | Historical URL discovery | Surfaces forgotten endpoints, old params |
| **ffuf** | Directory and parameter fuzzing | Discovers unlisted paths and inputs |
| **Nuclei template management UI** | Template browsing/selection | Reproducible, targeted scanning |
| **Custom Nuclei templates** | User-supplied YAML templates | Program-specific checks |

### 3. No Scheduled / Recurring Scans (High)
**Rating impact: −0.5 pt**

Bug bounty programs continuously add scope. dragonflAI only supports one-off manual runs. There is no cron-like scheduling, no monitoring for new assets, and no notification system for newly discovered findings.

### 4. Weak Intelligent Prioritization (Medium)
**Rating impact: −0.5 pt**

All detection signals receive a confidence score, but there is no automated ranking of which findings to pursue first. There are no trending patterns, no "easy wins" heuristic (e.g., first-seen subdomains with admin panels), and no behavioral anomaly detection across runs.

### 5. No OSINT Integration (Medium)

Public attack surface sources are untapped:
- Shodan / Censys (exposed services)
- Certificate Transparency logs (beyond subfinder)
- GitHub dorking (leaked secrets in code)
- Google/Bing dorks

### 6. Limited Payload Generation (Medium)

Detection is purely passive pattern matching. The platform cannot:
- Generate context-aware test payloads (XSS, SQLi, SSRF probes)
- Integrate with fuzzing tools (ffuf, wfuzz)
- Perform active parameter tampering beyond Nuclei templates

### 7. Reporting Gaps (Low-Medium)

- No direct platform submission (HackerOne API, Bugcrowd API)
- No template customization UI
- No automatic business-impact context
- No scheduled batch report generation

### 8. Analytics & Observability (Low)

- No dashboard with historical trends across runs
- No false positive rate tracking
- No "time to find" or finding velocity metrics
- No asset growth charts

### 9. No Multi-User Support (Low)

Single-researcher focus means no shared programs, no team permissions, no comment threads on findings, and no concurrent editing safeguards.

### 10. Mobile Target Support Missing (Low)

No APK/IPA endpoint extraction, no mobile-specific vulnerability checks (deep links, exported activities, insecure storage).

---

## Improvement Roadmap Priority

| Priority | Item | Effort |
|----------|------|--------|
| 🔴 Critical | Implement working LLM providers (Ollama, OpenAI, Anthropic) | Low — interfaces exist |
| 🔴 Critical | Add Katana + GAU recon tools | Low — existing tool pattern |
| 🟠 High | Scheduled/recurring scans | Medium |
| 🟠 High | OSINT integrations (Shodan, CT logs) | Medium |
| 🟡 Medium | Intelligent finding prioritization | Medium |
| 🟡 Medium | Context-aware payload generation via LLM | High |
| 🟢 Low | HackerOne / Bugcrowd API submission | Medium |
| 🟢 Low | Analytics dashboard | Medium |

---

## Conclusion

dragonflAI is a well-engineered platform with a responsible safety model and an excellent plugin architecture. It is production-quality infrastructure waiting for the AI features to be turned on. With working LLM providers, Katana/GAU integration, and scheduled scanning, it would be a legitimate competitive tool for bug bounty researchers. In its current state it functions as a solid **recon + organization platform** rather than a true AI-driven hunting assistant.
