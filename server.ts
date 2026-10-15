import express from 'express';
import dotenv from 'dotenv';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { executeAudit, getReportById } from './src/lib/audit-service.ts';
import { generateAuditMarkdown } from './src/lib/markdown-generator.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = Number(process.env.PORT) || 3000;
const isProduction = process.env.NODE_ENV === 'production';

app.disable('x-powered-by');

// Internal-tool access gate. In production, the app fails closed unless both
// credentials are configured. Browser Basic Auth protects the UI and API.
app.use((req, res, next) => {
  if (req.path === '/api/health') return next();
  if (!isProduction) return next();

  const username = process.env.AUDITOR_USERNAME;
  const password = process.env.AUDITOR_PASSWORD;
  if (!username || !password) {
    return res.status(503).send('Auditor access is not configured.');
  }

  res.setHeader('WWW-Authenticate', 'Basic realm="Auditor Internal", charset="UTF-8"');
  const header = req.headers.authorization || '';
  if (!header.startsWith('Basic ')) {
    return res.status(401).send('Authentication required.');
  }

  let decoded = '';
  try {
    decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
  } catch {
    return res.status(401).send('Authentication required.');
  }

  const separator = decoded.indexOf(':');
  const suppliedUser = separator >= 0 ? decoded.slice(0, separator) : '';
  const suppliedPassword = separator >= 0 ? decoded.slice(separator + 1) : '';
  if (suppliedUser !== username || suppliedPassword !== password) {
    return res.status(401).send('Authentication required.');
  }
  return next();
});
if (isProduction) app.set('trust proxy', 1);
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});
app.use(express.json({ limit: '1mb', strict: true }));

// Lightweight per-process guard. Use a shared limiter before scaling to multiple instances.
const auditRequests = new Map<string, number[]>();
const RATE_WINDOW_MS = 15 * 60 * 1000;
const RATE_MAX_REQUESTS = 10;
app.use('/api/audit', (req, res, next) => {
  const now = Date.now();
  const key = req.ip || req.socket.remoteAddress || 'unknown';
  const recent = (auditRequests.get(key) || []).filter((time) => now - time < RATE_WINDOW_MS);
  if (recent.length >= RATE_MAX_REQUESTS) {
    res.setHeader('Retry-After', String(Math.ceil((RATE_WINDOW_MS - (now - recent[0])) / 1000)));
    return res.status(429).json({ error: 'Audit limit reached. Try again in a few minutes.' });
  }
  recent.push(now);
  auditRequests.set(key, recent);

  // Keep this process-local map bounded during long-running deployments.
  if (auditRequests.size > 5000) {
    for (const [ip, timestamps] of auditRequests) {
      if (!timestamps.some((time) => now - time < RATE_WINDOW_MS)) auditRequests.delete(ip);
    }
  }
  next();
});

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

app.post('/api/audit/batch', async (req, res) => {
  const targets = req.body?.targets;
  if (!Array.isArray(targets) || targets.length < 1 || targets.length > 5) {
    return res.status(400).json({ error: 'Provide between 1 and 5 audit targets.' });
  }
  if (targets.some((item) => !item || typeof item.target !== 'string' || !item.target.trim())) {
    return res.status(400).json({ error: 'Each batch item must include a target URL.' });
  }

  const results: Array<{ index: number; target: string; report?: unknown; error?: string }> = [];
  let nextIndex = 0;
  const worker = async () => {
    while (true) {
      const index = nextIndex++;
      if (index >= targets.length) return;
      const item = targets[index];
      try {
        const report = await executeAudit({ type: 'url', target: item.target.trim() });
        results[index] = { index, target: item.target, report };
      } catch (error: unknown) {
        results[index] = { index, target: item.target, error: error instanceof Error ? error.message : 'Audit failed.' };
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(2, targets.length) }, () => worker()));
  return res.json({ total: targets.length, completed: results.filter((item) => item.report).length, results });
});

app.post('/api/audit', async (req, res) => {
  try {
    const { type, target, code, language, filename } = req.body ?? {};
    if (type !== 'url' && type !== 'code') {
      return res.status(400).json({ error: "Invalid audit type. Must be 'url' or 'code'." });
    }
    if (type === 'url' && (typeof target !== 'string' || !target.trim())) {
      return res.status(400).json({ error: 'Target URL is required.' });
    }
    if (type === 'code' && (typeof code !== 'string' || !code.trim())) {
      return res.status(400).json({ error: 'Source code content is required.' });
    }
    if (typeof target === 'string' && target.length > 2048) {
      return res.status(400).json({ error: 'Target URL is too long.' });
    }
    if (typeof code === 'string' && code.length > 200_000) {
      return res.status(413).json({ error: 'Source code is limited to 200,000 characters per audit.' });
    }

    const report = await executeAudit({
      type,
      target: typeof target === 'string' ? target : (typeof filename === 'string' ? filename : 'Code Snippet'),
      code,
      language,
      filename,
    });
    return res.json(report);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Audit execution failed.';
    // Known validation/fetch failures are safe to explain; avoid leaking internal stack traces.
    const status = /required|valid|allowed|supported|private|public|resolv|redirect|larger than|timed out|reached|cannot be audited|cannot be empty|limited to/i.test(message) ? 400 : 502;
    console.error('Audit execution failed:', message);
    return res.status(status).json({ error: message });
  }
});

app.get('/api/report/:id/compare/:previousId', async (req, res) => {
  try {
  const current = await getReportById(req.params.id);
  const previous = await getReportById(req.params.previousId);
  if (!current || !previous) return res.status(404).json({ error: 'Both reports must exist to compare them.' });
  if (current.target.type !== previous.target.type || current.target.target.replace(/\/$/, '') !== previous.target.target.replace(/\/$/, '')) {
    return res.status(400).json({ error: 'Reports must target the same URL or code file.' });
  }
  const signature = (issue: (typeof current.issues)[number]) => `${issue.category}|${issue.title.toLowerCase().trim()}`;
  const previousIssues = new Map(previous.issues.map((issue) => [signature(issue), issue]));
  const currentIssues = new Map(current.issues.map((issue) => [signature(issue), issue]));
  const added = current.issues.filter((issue) => !previousIssues.has(signature(issue)));
  const resolved = previous.issues.filter((issue) => !currentIssues.has(signature(issue)));
  return res.json({
    target: current.target.target,
    currentReportId: current.id,
    previousReportId: previous.id,
    currentCreatedAt: current.createdAt,
    previousCreatedAt: previous.createdAt,
    scoreDelta: current.overallScore - previous.overallScore,
    verdictChanged: current.verdict !== previous.verdict,
    previousVerdict: previous.verdict,
    currentVerdict: current.verdict,
    addedFindings: added,
    resolvedFindings: resolved,
    unchangedFindingCount: current.issues.length - added.length,
  });
  } catch (error) {
    console.error('Report comparison failed:', error instanceof Error ? error.message : 'Unknown error');
    return res.status(500).json({ error: 'Unable to compare reports right now.' });
  }
});

app.get('/api/report/:id', async (req, res) => {
  try {
    const report = await getReportById(req.params.id);
    if (!report) return res.status(404).json({ error: 'Report not found or expired.' });
    return res.json(report);
  } catch (error) {
    console.error('Report retrieval failed:', error instanceof Error ? error.message : 'Unknown error');
    return res.status(500).json({ error: 'Unable to retrieve report right now.' });
  }
});

app.get('/api/report/:id/md', async (req, res) => {
  try {
    const report = await getReportById(req.params.id);
    if (!report) return res.status(404).send('# Error: Report not found or expired.');
    const markdown = generateAuditMarkdown(report);
    if (req.query.download === 'true') {
      res.setHeader('Content-Disposition', `attachment; filename="audit-${report.id}.md"`);
    }
    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    return res.send(markdown);
  } catch (error) {
    console.error('Markdown report export failed:', error instanceof Error ? error.message : 'Unknown error');
    return res.status(500).send('# Error: Unable to export report right now.');
  }
});

async function startServer() {
  if (!isProduction) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true, hmr: process.env.DISABLE_HMR !== 'true' },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => res.sendFile(path.resolve(distPath, 'index.html')));
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Auditor server listening on port ${PORT} (${isProduction ? 'production' : 'development'})`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
