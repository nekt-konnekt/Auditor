import express from 'express';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import { executeAudit, getReportById } from './src/lib/audit-service.ts';
import { generateAuditMarkdown } from './src/lib/markdown-generator.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;

app.use(express.json({ limit: '10mb' }));

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// Run audit
app.post('/api/audit', async (req, res) => {
  try {
    const { type, target, code, language, filename } = req.body;
    if (!type || (type !== 'url' && type !== 'code')) {
      return res.status(400).json({ error: "Invalid audit type. Must be 'url' or 'code'." });
    }
    if (type === 'url' && !target) {
      return res.status(400).json({ error: 'Target URL is required.' });
    }
    if (type === 'code' && !code) {
      return res.status(400).json({ error: 'Source code content is required.' });
    }

    const report = await executeAudit({
      type,
      target: target || filename || 'Code Snippet',
      code,
      language,
      filename,
    });

    res.json(report);
  } catch (err: any) {
    console.error('Audit execution error:', err);
    res.status(500).json({ error: err.message || 'Audit execution failed.' });
  }
});

// Get report by ID
app.get('/api/report/:id', (req, res) => {
  const report = getReportById(req.params.id);
  if (!report) {
    return res.status(404).json({ error: 'Report not found or expired.' });
  }
  res.json(report);
});

// Download/view report as Markdown
app.get('/api/report/:id/md', (req, res) => {
  const report = getReportById(req.params.id);
  if (!report) {
    return res.status(404).send('# Error: Report not found or expired.');
  }
  const markdown = generateAuditMarkdown(report);
  const download = req.query.download === 'true';

  if (download) {
    const filename = `audit-${report.id}.md`;
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  }
  res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
  res.send(markdown);
});

async function startServer() {
  const isProduction = process.env.NODE_ENV === 'production';

  if (!isProduction) {
    // In development, mount Vite's dev server middleware
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true, hmr: process.env.DISABLE_HMR !== 'true' },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    // In production, serve the built static client
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.resolve(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Auditor server running on http://0.0.0.0:${PORT} in ${isProduction ? 'production' : 'development'} mode`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
