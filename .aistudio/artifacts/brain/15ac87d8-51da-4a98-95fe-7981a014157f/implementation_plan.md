# Auditor — Full-Spectrum Web & Code Intelligence Platform

A high-performance audit platform that performs dual-mode analysis: deep live website inspections (SEO structure, security headers, speed benchmarks, semantic accessibility) and static code security audits (vulnerability detection, code quality anti-patterns, OWASP risks, and remediation patches). Built with an interactive developer studio dashboard, exportable Markdown reports, and shareable audit permalinks.

### User Review & Critical Decisions

> [!IMPORTANT]
> The following architectural and design decisions reflect your confirmed choices from Phase 1:

- **Confirmed Decision 1 (Dual Audit Scope)**: Supports both **Website Audits** (SEO health, HTTP/security headers, accessibility markup, metadata tags, resource weight) and **Code & Security Audits** (vulnerability scanning, OWASP top 10 detection, code smells, syntax quality, and concrete line-by-line fix proposals).
- **Confirmed Decision 2 (Flexible Ingestion)**: Supports both **Live URL Inspection** (real-time crawler and HTTP header/HTML analyzer) and **Code/File Uploads** (multi-file paste, drag-and-drop, and syntax-highlighted snippets across TypeScript, JavaScript, Python, Go, Rust, Solidity, and HTML/CSS).
- **Confirmed Decision 3 (Dashboard & Export)**: Full interactive report dashboard with breakdown tabs, issue severity filtering, one-click Markdown export (`.md`), copyable executive summary, and permalink/URL-state sharing.
- **Confirmed Decision 4 (Aesthetic Direction)**: Clean modern light developer studio aesthetic adhering to strict anti-slop rules (subtle hairline borders, 60-30-10 color discipline with slate and emerald accents, tabular figures, no pill badge sandwiches, and responsive 1440px desktop layout).

---

### 1. Overview & Core Concept

- **What It Does**: Auditor enables developers, DevOps engineers, and digital agencies to submit either a live website URL or source code files. It executes targeted diagnostic rules alongside deep Gemini-powered semantic analysis, producing categorized audit cards with severity ratings (Critical, High, Medium, Low, Passed), line/DOM-level evidence, and automated remediation code snippets.
- **Target Audience / Persona**: Full-stack developers, security engineers, webmasters, and technical leads auditing deployments before release or performing client website assessments.
- **Key Value**: Replaces multiple disparate tools (Lighthouse-style SEO/accessibility scanners, security header analyzers, and static security linters) into a unified, zero-friction developer workbench with instant actionable fixes.

---

### 2. User Experience & Visual Design

- **Key User Flows**:
  1. **Audit Initiation**: The user lands on a clean studio workspace with a dual-mode trigger switch: **Live URL Inspection** or **Source Code Security**.
     - In URL mode: Enter any web URL (with pre-built sample targets for quick testing), select scan intensity, and click "Run Audit".
     - In Code mode: Paste source code or select sample vulnerable files (e.g., SQL injection, XSS vulnerability, insecure regex, hardcoded secrets), choose language, and run the audit.
  2. **Live Scanning Progress**: Multi-step pipeline tracker showing active diagnostic checks (Header Extraction $\rightarrow$ DOM Parsing $\rightarrow$ Security Heuristics $\rightarrow$ Gemini Synthesis).
  3. **Interactive Report View**:
     - **Header Bar**: Target URL or File name, timestamp, overall health score with breakdown radial gauges, and quick action buttons ("Export Markdown", "Share Link", "New Audit").
     - **Filter & Search Bar**: Filter findings by Severity (Critical, High, Medium, Low, Passed) and Category (SEO, Security, Accessibility, Performance, Code Quality).
     - **Issue Detail Cards**: Clear title, human explanation, affected snippet / DOM selector, standard CVE / CWE / OWASP classification where applicable, and "Recommended Fix" with copyable diff.
     - **Markdown Preview Modal / Direct Download**: Formatted `.md` audit document ready for GitHub PRs or executive delivery.
  4. **Recent Audits & History**: Client-side persisted list of previous audits for quick re-inspection and side-by-side score comparison.

- **Visual Identity & Theme**:
  - *Aesthetic Direction*: Clean modern light developer studio aesthetic. Crisp neutral canvas (`#F8FAFC` and `#FFFFFF`), cool slate borders (`#E2E8F0`), charcoal high-contrast typography (`#0F172A`), and emerald accent highlights (`#059669`).
  - *Typography & Tabular Discipline*: `Plus Jakarta Sans` for clean, structured section headers and navigation; `JetBrains Mono` / `tabular-nums` for all metrics, code snippets, line numbers, and timestamps.
  - *Component Styling & Layout*: Anti-slop discipline: zero static pill badges (clean text with typographic `·` separators), no decorative pulsating dots, single-elevation cards with 1px hairline borders, balanced headline typography, and full 1440px desktop viewport presence.

---

### 3. Key Product Decisions & Trade-Offs

- **Decision 1: Hybrid Client-Server Audit Architecture**
  - *Chosen Approach*: Server-side Express API endpoint (`/api/audit`) that handles external URL scraping (bypassing browser CORS restrictions), extracts live HTTP security headers and HTML DOM metadata, and invokes `@google/genai` (`gemini-3.8-flash`) server-side for in-depth vulnerability intelligence and remediation advice.
  - *Why*: Browsers block cross-origin requests to arbitrary URLs due to CORS; the server proxy guarantees reliable crawling of any live website. Server-side execution also keeps the Gemini API key strictly secure.
  - *Alternatives Considered*: Client-only fetch was rejected due to inevitable CORS failures on 99% of live websites.

- **Decision 2: Comprehensive Deterministic Heuristics + AI Deep Analysis**
  - *Chosen Approach*: Hybrid detection pipeline. Standard deterministic rules immediately evaluate known vectors (HSTS, Content-Security-Policy, X-Frame-Options, viewport tags, OpenGraph tags, alt attribute coverage, heading hierarchy, hardcoded regex keys) while Gemini models deep contextual logic flaws, OWASP vulnerabilities, and contextual SEO/accessibility nuances.
  - *Why*: Deterministic checks provide instant, reliable 100% accurate metrics, while LLM reasoning catches subtle application logic flaws and generates customized code patches.

- **Decision 3: Storage & Link Sharing Strategy**
  - *Chosen Approach*: In-memory server report cache with compressed URL hash state and client-side `localStorage` backup. Reports can be loaded instantly via unique IDs (`/r/:id` or state hash), downloaded as standard Markdown (`.md`), or copied to clipboard.
  - *Why*: Zero authentication friction for instant audit generation, while providing robust permalink sharing and exportability.

---

### 4. Technical Architecture & Data Strategy

```
┌────────────────────────────────────────────────────────────────────────┐
│                          AUDITOR CLIENT (Vite + React)                 │
│                                                                        │
│   ┌─────────────────────┐   ┌──────────────────────────────────────┐   │
│   │   Navigation Bar    │   │  Audit Workspace (URL / Code Tabs)   │   │
│   └──────────┬──────────┘   └──────────────────┬───────────────────┘   │
│              │                                 │                       │
│              ▼                                 ▼                       │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │                 Interactive Report Dashboard                   │   │
│   │  ┌──────────────┐ ┌──────────────┐ ┌─────────────────────────┐  │   │
│   │  │ Score Strip  │ │ Category Nav │ │ Issue Cards & Diff Fix  │  │   │
│   │  └──────────────┘ └──────────────┘ └─────────────────────────┘  │   │
│   │  ┌───────────────────────────────────────────────────────────┐  │   │
│   │  │   Markdown Export Generator & Permalink Sharing Engine    │  │   │
│   │  └───────────────────────────────────────────────────────────┘  │   │
│   └────────────────────────────────┬───────────────────────────────┘   │
└────────────────────────────────────┼───────────────────────────────────┘
                                     │  POST /api/audit
                                     │  GET  /api/report/:id/md
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        EXPRESS SERVER (server.ts)                      │
│                                                                        │
│  ┌──────────────────┐    ┌────────────────────┐    ┌─────────────────┐ │
│  │ Live URL Crawler │    │ Deterministic Rule │    │ Gemini 3.8 SDK  │ │
│  │ & Header Scraper │───▶│ Heuristics Engine  │───▶│ AI Security     │ │
│  │ (Cheerio / HTML) │    │ (Security & SEO)   │    │ Intelligence    │ │
│  └──────────────────┘    └────────────────────┘    └─────────────────┘ │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Report Store & Markdown Serializer (lib/audit.ts & lib/md.ts)     │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

- **Interactive State & Event Mapping**:
  - `auditType`: `'url' | 'code'` — toggles the active ingestion interface.
  - `activeReport`: Current audit result entity containing scores, metadata, category summaries, and finding list.
  - `filters`: Multi-dimensional filtering by severity (`critical`, `high`, `medium`, `low`, `passed`) and category (`seo`, `security`, `accessibility`, `performance`, `quality`).
  - `exportMarkdown`: Serializes structured audit findings into clean GitHub-flavored Markdown tables and code fences.
  - `shareLink`: Generates a shareable URL that loads the exact report snapshot.
