import express from 'express';
import dotenv from 'dotenv';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { timingSafeEqual } from 'node:crypto';
import { executeAudit, getReportById } from './src/lib/audit-service.ts';
import { generateAuditMarkdown } from './src/lib/markdown-generator.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = Number(process.env.PORT) || 3000;
const isProduction = process.env.NODE_ENV === 'production';

app.disable('x-powered-by');

// Keep the internal tool protected even when deployed outside Vercel. Vercel
// Deployment Protection should remain enabled as a second layer, not the only layer.
if (isProduction) app.set('trust proxy', 1);

function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

function internalAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
  if (!isProduction || req.path === '/api/health') return next();

  const username = process.env.AUDITOR_USERNAME;
  const password = process.env.AUDITOR_PASSWORD;
  // Fail closed: never accidentally publish an unprotected internal deployment.
  if (!username || !password) {
    console.error('Auditor internal auth is not configured; refusing protected request.');
    return res.status(503).json({ error: 'Internal access is not configured. Set AUDITOR_USERNAME and AUDITOR_PASSWORD.' });
  }

  const header = req.headers.authorization || '';
  const match = /^Basic\\s+([A-Za-z0-9+/=]+)$/i.exec(header);
  if (!match) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Auditor Internal", charset="UTF-8"');
    return res.status(401).send('Authentication required.');
  }

  let decoded = '';
  try { decoded = Buffer.from(match[1], 'base64').toString('utf8'); } catch { /* reject below */ }
  const separator = decoded.indexOf(':');
  const suppliedUser = separator >= 0 ? decoded.slice(0, separator) : '';
  const suppliedPassword = separator >= 0 ? decoded.slice(separator + 1) : '';
  if (!safeEqual(suppliedUser, username) || !safeEqual(suppliedPassword, password)) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Auditor Internal", charset="UTF-8"');
    return res.status(401).send('Authentication required.');
  }
  return next();
}
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});
app.use(express.json({ limit: '1mb', strict: true }));
app.use(internalAuth);

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

app.get('/api/report/:id', (req, res) => {
  const report = getReportById(req.params.id);
  if (!report) return res.status(404).json({ error: 'Report not found or expired.' });
  return res.json(report);
});

app.get('/api/report/:id/md', (req, res) => {
  const report = getReportById(req.params.id);
  if (!report) return res.status(404).send('# Error: Report not found or expired.');
  const markdown = generateAuditMarkdown(report);
  if (req.query.download === 'true') {
    res.setHeader('Content-Disposition', `attachment; filename="audit-${report.id}.md"`);
  }
  res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
  return res.send(markdown);
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

export { app };
export default app;

// Vercel invokes the exported Express app as a serverless function. Keep the
// listener for Railway and local development, but never open a port in Vercel.
if (process.env.VERCEL !== '1') {
  startServer().catch((err) => {
    console.error('Failed to start server:', err);
    process.exit(1);
  });
}
