# Auditor

<p align="center">
  <strong>Website & source-code intelligence for shipping with confidence.</strong><br />
  Inspect public websites, review GitHub repository hygiene, and scan pasted code for actionable risks.
</p>

<p align="center">
  <img alt="TypeScript" src="https://img.shields.io/badge/TypeScript-5B8DEF?style=for-the-badge&logo=typescript&logoColor=white" />
  <img alt="React" src="https://img.shields.io/badge/React-149ECA?style=for-the-badge&logo=react&logoColor=white" />
  <img alt="Vite" src="https://img.shields.io/badge/Vite-7C3AED?style=for-the-badge&logo=vite&logoColor=white" />
  <img alt="Security first" src="https://img.shields.io/badge/Security-first-059669?style=for-the-badge&logo=owasp&logoColor=white" />
</p>

---

## What it does

- **Website checks** — inspect HTTP status, response timing, security headers, SEO metadata and accessible markup.
- **GitHub repository checks** — review public repository metadata and common hygiene signals such as security policy, dependency manifests, and license presence.
- **Source-code review** — run deterministic pattern checks and, when configured, optional Gemini-assisted analysis.
- **Actionable reports** — filter findings by severity/category and export a Markdown report.
- **Local history** — keep recent report summaries in the browser.

Auditor is an early-stage diagnostic tool, not a penetration-testing suite or a guarantee that a target is secure. Verify important findings manually.

## Run locally

Requirements: Node.js 22.12+ and Bun (the repository includes `bun.lock`).

```bash
bun install
cp .env.example .env
# Optional: add GEMINI_API_KEY to enable AI-assisted findings.
bun run dev
```

Open the local URL printed by Vite. The development server exposes the API on port 3000.

## Environment

| Variable | Required | Purpose |
| --- | --- | --- |
| `GEMINI_API_KEY` | No | Enables optional Gemini-assisted analysis. Without it, deterministic checks still run. |
| `PORT` | No | HTTP port; defaults to 3000. |
| `NODE_ENV` | No | Set to `production` to serve the built frontend. |

Never commit real API keys or private source code. Do not paste secrets, credentials, or customer data into the code auditor.

## Build and run

```bash
bun run build
NODE_ENV=production bun run start
```

The Express server serves the built Vite app and the `/api/*` endpoints from one process.

## Deployment notes

This application is a **single Node.js web service**, not a static-only frontend. Deploy it to a Node-compatible host (for example Railway) with the repository root as the service root and the following commands:

- Build: `bun run build`
- Start: `bun run start`
- Health check: `/api/health`
- Port: use the platform-provided `PORT`

Set `GEMINI_API_KEY` in the host's secret/environment settings only if AI analysis is wanted. Never put it in Vite client variables.

### Current production limitations

- Report permalinks are kept in a bounded in-memory cache for up to one hour. They can stop working after a restart and are not reliable across multiple instances. Add durable storage before depending on shared reports.
- The built-in request limiter is process-local. Use a shared rate limiter and monitoring before scaling horizontally.
- Website auditing only accepts public HTTP/HTTPS pages, validates DNS answers, follows redirects manually, and caps HTML downloads at 2 MB. This is defense-in-depth, not a substitute for infrastructure-level egress restrictions.
- GitHub repository auditing currently targets public repositories; private repository auditing is not supported.

## Security

Please do not use Auditor to scan systems without permission. Report suspected vulnerabilities in Auditor privately to the repository maintainer rather than publishing exploit details in public issues.

---

<p align="center"><strong>Inspect evidence. Prioritize risk. Ship with more confidence.</strong></p>
