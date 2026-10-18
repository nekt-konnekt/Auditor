# Auditor

<p align="center">
  <strong>Website and source-code intelligence for making better release decisions.</strong><br />
  Audit public websites, review public GitHub repositories, and scan pasted code for actionable risks.
</p>

<p align="center">
  <img alt="TypeScript" src="https://img.shields.io/badge/TypeScript-5B8DEF?style=for-the-badge&logo=typescript&logoColor=white" />
  <img alt="React" src="https://img.shields.io/badge/React-149ECA?style=for-the-badge&logo=react&logoColor=white" />
  <img alt="Vite" src="https://img.shields.io/badge/Vite-7C3AED?style=for-the-badge&logo=vite&logoColor=white" />
  <img alt="Security-first" src="https://img.shields.io/badge/Security-first-059669?style=for-the-badge&logo=owasp&logoColor=white" />
</p>

---

## What Auditor does

- **Website audits** — inspect HTTP status and response timing, security headers, SEO metadata, accessible markup, and selected public exposure signals.
- **GitHub repository audits** — review public repository metadata and common hygiene signals such as security policy, dependency manifests, and license presence.
- **Source-code checks** — run deterministic pattern checks and request optional AI-assisted analysis.
- **AI provider resilience** — use Ollama Cloud as the primary AI provider, with configured providers such as Groq, Gemini, and Alibaba available as fallbacks.
- **Deterministic reports** — if AI providers are unavailable or fail, built-in checks can still produce a report. AI enrichment is supplementary; a completed report does not by itself prove that an AI provider responded.
- **Actionable output** — review findings by severity and category, and export Markdown or PDF reports where supported by the interface.
- **Audit history and comparisons** — use the available workspace features to revisit audits and compare results. Persistence depends on the configured storage backend.

## Production status and appropriate use

Auditor is intended to support **internal, supervised client-site assessments**. Treat it as a diagnostic aid, not as a certification, a comprehensive penetration test, or a guarantee that a website is secure, accessible, compliant, or ready to launch.

Before sharing a report with a client:

1. Review critical and high-severity findings manually and confirm important findings against the target.
2. Check that the readiness verdict agrees with the individual findings; severity and readiness are separate signals in the current rules.
3. Explain the scope and limitations of the audit. Do not present untested areas as passed.
4. Use authorized targets only, and obtain permission before testing client systems.

### Known scope limitations

An ordinary website audit does **not** necessarily include:

- Browser-rendered testing or complete JavaScript-driven user journeys.
- Real-user monitoring or full Core Web Vitals measurement.
- Authenticated pages, account-specific workflows, or exhaustive route coverage.
- A full penetration test, manual security review, or exhaustive vulnerability assessment.

Performance scores may be based on initial HTML fetch timing rather than real-user performance. Findings can be false positives or false negatives; confirm material risks independently.

## Run locally

Requirements: Node.js 22.12+ and Bun (the repository includes `bun.lock`).

```bash
bun install
cp .env.example .env
bun run dev
```

Open http://localhost:3000. In development, the Express server mounts Vite and exposes the API on the same port.

## AI providers and environment

Copy `.env.example` and set only the providers you intend to use. Keep every API key on the server; never expose provider credentials through client-side variables or commit them to Git.

| Variable | Purpose |
| --- | --- |
| `AI_PRIMARY_PROVIDER` | Primary AI provider; defaults to `ollama-cloud`. |
| `OLLAMA_API_KEY` | Server-side Ollama Cloud API key. |
| `OLLAMA_BASE_URL` | Ollama-compatible API endpoint; defaults to `https://ollama.com/v1`. |
| `OLLAMA_MODEL` | Ollama Cloud model; defaults to `gemma4:31b`. |
| `AI_FALLBACK_PROVIDERS` | Ordered fallback list; defaults to `groq,gemini,alibaba`. |
| `GROQ_API_KEY`, `GROQ_MODEL` | Optional Groq fallback credentials and model. |
| `GEMINI_API_KEY`, `GEMINI_MODEL` | Optional Gemini fallback credentials and model. |
| `DASHSCOPE_API_KEY`, `DASHSCOPE_BASE_URL`, `DASHSCOPE_MODEL` | Optional Alibaba Cloud Model Studio fallback. |
| `OPENROUTER_API_KEY`, `OPENROUTER_MODEL` | Optional OpenRouter fallback. |
| `AI_API_KEY`, `AI_BASE_URL`, `AI_MODEL` | Optional custom OpenAI-compatible provider settings. |
| `AUDITOR_USERNAME`, `AUDITOR_PASSWORD` | Strong, unique credentials for internal-tool Basic Auth; required in production. |
| `DATABASE_URL` | Optional Neon/PostgreSQL connection for durable report persistence and cross-instance retrieval/comparisons when database persistence is enabled. |
| `APP_URL` | Optional public URL where Auditor is hosted. |

Provider availability depends on valid server-side credentials, provider access, and model availability. If all configured AI providers fail, deterministic checks should still be used; AI-generated interpretation may be missing. A successful audit alone does not identify which provider answered.

## Build and run

```bash
bun run build
NODE_ENV=production bun run start
```

The Express server serves the built Vite application and the `/api/*` endpoints from one process.

## Deployment notes

Deploy as a Node.js application, not as a static-only frontend. Configure the host to use:

- **Build:** `bun run build`
- **Start:** `bun run start`
- **Health check:** `/api/health`
- **Port:** the platform-provided `PORT`

Set production secrets in the hosting provider's secret/environment settings. Ensure internal authentication is configured before exposing the tool to users.

### Operational limitations to plan for

- If durable database persistence is not configured, report availability and comparisons may not persist across restarts or multiple instances.
- Process-local rate limiting is not sufficient by itself for horizontally scaled production use; use shared rate limiting and monitoring before scaling.
- Website auditing is limited to public HTTP/HTTPS pages, validates DNS answers, follows redirects manually, and caps HTML downloads at 2 MB. This is defense-in-depth, not a replacement for infrastructure-level egress restrictions.
- GitHub repository auditing currently targets public repositories; private repository auditing is not supported.

## Security

Do not use Auditor to scan systems without permission. Keep credentials and private source code out of reports, logs, issues, and commits. Report suspected vulnerabilities in Auditor privately to the repository maintainer rather than publishing exploit details in public issues.

---

<p align="center"><strong>Inspect evidence. Prioritize risk. Make decisions with confidence.</strong></p>
