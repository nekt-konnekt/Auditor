import * as cheerio from 'cheerio';
import { AuditIssue, AuditReport, Category, CategoryScore } from '../types/audit.ts';

export interface UrlAuditInput {
  url: string;
  statusCode: number;
  headers: Record<string, string>;
  html: string;
  responseTimeMs: number;
}

export interface CodeAuditInput {
  code: string;
  language: string;
  filename: string;
}

/**
 * Deterministic website inspection rules for headers, SEO, and DOM accessibility
 */
export function runUrlDeterministicAudit(input: UrlAuditInput): {
  issues: AuditIssue[];
  metrics: Record<string, string | number | boolean>;
} {
  const issues: AuditIssue[] = [];
  const metrics: Record<string, string | number | boolean> = {};
  const $ = cheerio.load(input.html);

  const headers = Object.fromEntries(
    Object.entries(input.headers).map(([k, v]) => [k.toLowerCase(), v])
  );

  // 1. SECURITY CHECKS
  // Check 1: HTTPS
  const isHttps = input.url.startsWith('https://');
  metrics['HTTPS Enabled'] = isHttps;
  if (!isHttps) {
    issues.push({
      id: 'sec-https',
      category: 'security',
      severity: 'critical',
      title: 'Insecure HTTP Transport Protocol',
      description: 'The target website is serving traffic over plaintext HTTP without TLS encryption.',
      impact: 'Allows man-in-the-middle (MITM) attackers to sniff credentials, inject malicious scripts, or tamper with data in transit.',
      remediation: 'Obtain an SSL/TLS certificate (e.g., via Let’s Encrypt) and enforce automatic HTTP-to-HTTPS 301 redirection on your web server.',
      references: [{ title: 'MDN: Transport Layer Security', url: 'https://developer.mozilla.org/en-US/docs/Glossary/TLS' }],
    });
  } else {
    issues.push({
      id: 'sec-https-pass',
      category: 'security',
      severity: 'passed',
      title: 'Valid HTTPS Transport Protocol',
      description: 'The target is encrypted using HTTPS.',
      remediation: 'Maintain active TLS certificate renewal.',
    });
  }

  // Check 2: Content-Security-Policy
  const csp = headers['content-security-policy'];
  const weakCspPattern = /(?:unsafe-inline|unsafe-eval|(?:script-src|default-src)\s+[^;]*\*)/i;
  metrics['CSP Present'] = !!csp;
  if (!csp) {
    issues.push({
      id: 'sec-csp',
      category: 'security',
      severity: 'high',
      title: 'Missing Content-Security-Policy (CSP) Header',
      description: 'The HTTP response is missing a Content-Security-Policy header to restrict resource loading.',
      impact: 'Significantly increases vulnerability to Cross-Site Scripting (XSS), clickjacking, and data injection attacks.',
      remediation: "Configure the 'Content-Security-Policy' header to restrict script-src, object-src, and frame-ancestors to trusted origins only.",
      evidence: 'Header missing from response headers.',
      references: [{ title: 'OWASP CSP Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html' }],
    });
  } else if (weakCspPattern.test(csp)) {
    issues.push({
      id: 'sec-csp-weak',
      category: 'security',
      severity: 'medium',
      title: 'Content-Security-Policy May Be Too Permissive',
      description: 'The policy contains broad wildcards or unsafe script directives. Header presence alone does not establish an effective CSP.',
      impact: 'A permissive policy can reduce protection against injected scripts and unintended resource loading.',
      remediation: 'Review each directive, restrict script-src and default-src to trusted sources, remove unsafe-inline/unsafe-eval where practical, and define frame-ancestors explicitly.',
      evidence: csp.substring(0, 240) + (csp.length > 240 ? '...' : ''),
      references: [{ title: 'OWASP CSP Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html' }],
    });
  } else {
    issues.push({
      id: 'sec-csp-pass',
      category: 'security',
      severity: 'passed',
      title: 'Content-Security-Policy Configured',
      description: 'The website supplies a Content-Security-Policy header.',
      evidence: csp.substring(0, 80) + (csp.length > 80 ? '...' : ''),
      remediation: 'Ensure directives are restrictive and avoid "unsafe-inline" where possible.',
    });
  }

  // Check 3: Strict-Transport-Security (HSTS)
  const hsts = headers['strict-transport-security'];
  metrics['HSTS Present'] = !!hsts;
  if (!hsts) {
    issues.push({
      id: 'sec-hsts',
      category: 'security',
      severity: 'medium',
      title: 'Missing Strict-Transport-Security (HSTS) Header',
      description: 'The server does not mandate HTTPS connections via the HSTS response header.',
      impact: 'Users making initial HTTP requests may be susceptible to SSL stripping attacks before any redirection occurs.',
      remediation: 'Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` to your server response headers.',
    });
  } else {
    issues.push({
      id: 'sec-hsts-pass',
      category: 'security',
      severity: 'passed',
      title: 'HSTS Header Configured',
      description: 'Strict-Transport-Security is present, enforcing browser HTTPS communication.',
      evidence: hsts,
      remediation: 'Verify includeSubDomains and preload parameters.',
    });
  }

  // Check 4: X-Frame-Options
  const xfo = headers['x-frame-options'];
  metrics['X-Frame-Options'] = xfo || 'Not set';
  if (!xfo && (!csp || !csp.includes('frame-ancestors'))) {
    issues.push({
      id: 'sec-xfo',
      category: 'security',
      severity: 'medium',
      title: 'Clickjacking Protection Missing (X-Frame-Options)',
      description: 'Neither X-Frame-Options nor CSP frame-ancestors is configured to prevent embedding in iframes.',
      impact: 'Allows malicious third-party websites to frame this page and execute clickjacking attacks.',
      remediation: "Set `X-Frame-Options: SAMEORIGIN` or `DENY`, or specify `frame-ancestors 'self'` in CSP.",
    });
  } else {
    issues.push({
      id: 'sec-xfo-pass',
      category: 'security',
      severity: 'passed',
      title: 'Clickjacking Defense Enforced',
      description: 'The page is protected against unauthorized iframe embedding.',
      evidence: xfo || 'Protected via CSP frame-ancestors',
      remediation: 'Keep frame restrictions updated for all embedded routes.',
    });
  }

  // Check 5: X-Content-Type-Options
  const xcto = headers['x-content-type-options'];
  metrics['X-Content-Type-Options'] = xcto || 'Not set';
  if (!xcto || !xcto.toLowerCase().includes('nosniff')) {
    issues.push({
      id: 'sec-xcto',
      category: 'security',
      severity: 'low',
      title: 'Missing X-Content-Type-Options: nosniff',
      description: 'The server does not prevent MIME-type sniffing.',
      impact: 'Older or non-standard browsers may interpret non-executable MIME types as executable JavaScript.',
      remediation: 'Include `X-Content-Type-Options: nosniff` in all HTTP responses.',
    });
  } else {
    issues.push({
      id: 'sec-xcto-pass',
      category: 'security',
      severity: 'passed',
      title: 'MIME-Type Sniffing Protection Enabled',
      description: 'X-Content-Type-Options is set to nosniff.',
      remediation: 'Ensure this header applies across static assets and API routes.',
    });
  }

  // Check 6: Referrer-Policy
  const refPolicy = headers['referrer-policy'];
  if (!refPolicy) {
    issues.push({
      id: 'sec-refpolicy',
      category: 'security',
      severity: 'low',
      title: 'Missing Referrer-Policy Header',
      description: 'No explicit Referrer-Policy is declared.',
      impact: 'Sensitive query parameters or private paths could be leaked to external sites via the Referer header.',
      remediation: 'Set `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer`.',
    });
  }

  // 2. SEO CHECKS
  // Check Title
  const title = $('title').text().trim();
  metrics['Page Title'] = title || 'Missing';
  metrics['Title Length'] = title.length;
  if (!title) {
    issues.push({
      id: 'seo-title-missing',
      category: 'seo',
      severity: 'critical',
      title: 'Missing <title> Element',
      description: 'The HTML document does not contain a <title> tag in the <head>.',
      impact: 'Critical search indexing penalty; search engines cannot determine page subject and browser tabs show URL.',
      remediation: 'Add a descriptive <title> tag between 30 and 60 characters inside <head>.',
    });
  } else if (title.length < 20) {
    issues.push({
      id: 'seo-title-short',
      category: 'seo',
      severity: 'medium',
      title: 'Page Title is Sub-optimally Short',
      description: `Current title is only ${title.length} characters long: "${title}".`,
      impact: 'Fails to capitalize on search keyword density and search result real estate.',
      remediation: 'Expand the title to 30–60 characters to include primary brand and page intent keywords.',
      evidence: title,
    });
  } else if (title.length > 70) {
    issues.push({
      id: 'seo-title-long',
      category: 'seo',
      severity: 'low',
      title: 'Page Title May Be Truncated in SERPs',
      description: `Current title is ${title.length} characters long and exceeds standard 60-character search snippets.`,
      impact: 'Search engines will truncate the title with an ellipsis (...), hiding key terms.',
      remediation: 'Condense title to under 60 characters.',
      evidence: title,
    });
  } else {
    issues.push({
      id: 'seo-title-pass',
      category: 'seo',
      severity: 'passed',
      title: 'Optimal Title Length and Presence',
      description: `Title is well-formed (${title.length} characters).`,
      evidence: title,
      remediation: 'Maintain keyword relevance and unique titles across different routes.',
    });
  }

  // Check Meta Description
  const metaDesc = $('meta[name="description"]').attr('content') || $('meta[property="og:description"]').attr('content') || '';
  metrics['Meta Description'] = metaDesc ? `${metaDesc.substring(0, 50)}...` : 'Missing';
  metrics['Meta Description Length'] = metaDesc.length;
  if (!metaDesc) {
    issues.push({
      id: 'seo-desc-missing',
      category: 'seo',
      severity: 'high',
      title: 'Missing Meta Description',
      description: 'The page lacks a <meta name="description"> tag.',
      impact: 'Search engines will auto-generate snippets from random body text, decreasing organic click-through rates (CTR).',
      remediation: 'Add a compelling meta description tag of 120–160 characters summarizing the page value proposition.',
    });
  } else if (metaDesc.length < 50 || metaDesc.length > 165) {
    issues.push({
      id: 'seo-desc-length',
      category: 'seo',
      severity: 'low',
      title: `Meta Description Length Sub-optimal (${metaDesc.length} chars)`,
      description: 'Meta descriptions perform best when kept between 70 and 160 characters.',
      remediation: 'Tune description length to 120–155 characters for optimal snippet presentation.',
      evidence: metaDesc,
    });
  } else {
    issues.push({
      id: 'seo-desc-pass',
      category: 'seo',
      severity: 'passed',
      title: 'Meta Description Tag Optimized',
      description: `Meta description is present with ideal length (${metaDesc.length} chars).`,
      evidence: metaDesc,
      remediation: 'Ensure unique descriptions per page.',
    });
  }

  // Check Canonical Link
  const canonical = $('link[rel="canonical"]').attr('href');
  metrics['Canonical URL'] = canonical || 'Missing';
  if (!canonical) {
    issues.push({
      id: 'seo-canonical',
      category: 'seo',
      severity: 'medium',
      title: 'Missing Rel Canonical Link',
      description: 'No canonical URL tag (<link rel="canonical">) was detected.',
      impact: 'Duplicate URL parameters (tracking tags, query strings, protocol variations) can dilute search ranking signals.',
      remediation: 'Add `<link rel="canonical" href="https://example.com/page" />` inside the `<head>`.',
    });
  } else {
    issues.push({
      id: 'seo-canonical-pass',
      category: 'seo',
      severity: 'passed',
      title: 'Canonical Link Declared',
      description: 'Search engines are given an explicit preferred URL for indexation.',
      evidence: canonical,
      remediation: 'Verify canonical URL matches primary canonical host.',
    });
  }

  // Check OpenGraph Tags
  const ogTitle = $('meta[property="og:title"]').attr('content');
  const ogImage = $('meta[property="og:image"]').attr('content');
  metrics['OpenGraph Configured'] = !!(ogTitle && ogImage);
  if (!ogTitle || !ogImage) {
    issues.push({
      id: 'seo-og-tags',
      category: 'seo',
      severity: 'medium',
      title: 'Incomplete Social Media OpenGraph Tags',
      description: `Missing essential social cards (${!ogTitle ? 'og:title ' : ''}${!ogImage ? 'og:image' : ''}).`,
      impact: 'Links shared on LinkedIn, Twitter, Slack, and Facebook will display plain text or broken card previews.',
      remediation: 'Add `og:title`, `og:description`, `og:image`, and `og:url` tags to optimize social sharing CTR.',
    });
  } else {
    issues.push({
      id: 'seo-og-pass',
      category: 'seo',
      severity: 'passed',
      title: 'OpenGraph Social Card Meta Ready',
      description: 'og:title and og:image are properly declared.',
      evidence: `og:title="${ogTitle}"`,
      remediation: 'Test social card preview rendering.',
    });
  }

  // Check Viewport Meta
  const viewport = $('meta[name="viewport"]').attr('content');
  if (!viewport) {
    issues.push({
      id: 'seo-viewport',
      category: 'seo',
      severity: 'critical',
      title: 'Missing Viewport Meta Tag',
      description: 'The page does not declare a mobile viewport tag.',
      impact: 'Mobile browsers will render the desktop version in 980px zoom mode, failing mobile-friendliness audits.',
      remediation: 'Add `<meta name="viewport" content="width=device-width, initial-scale=1.0">`.',
    });
  } else {
    issues.push({
      id: 'seo-viewport-pass',
      category: 'seo',
      severity: 'passed',
      title: 'Responsive Mobile Viewport Declared',
      description: 'Viewport tag is present and configured.',
      evidence: viewport,
      remediation: 'Avoid user-scalable=no to preserve accessibility zoom capabilities.',
    });
  }

  // 3. ACCESSIBILITY CHECKS
  // Check HTML lang
  const htmlLang = $('html').attr('lang');
  metrics['HTML Lang'] = htmlLang || 'Missing';
  if (!htmlLang) {
    issues.push({
      id: 'a11y-lang',
      category: 'accessibility',
      severity: 'high',
      title: 'Missing lang Attribute on <html> Element',
      description: 'The root <html> tag lacks an explicit language declaration (e.g., lang="en").',
      impact: 'Screen readers cannot determine the correct language pronunciation rules, causing garbled speech output.',
      remediation: 'Add `lang="en"` (or the appropriate BCP 47 language code) to your `<html>` element.',
      domSelector: 'html',
    });
  } else {
    issues.push({
      id: 'a11y-lang-pass',
      category: 'accessibility',
      severity: 'passed',
      title: 'Document Language Declared',
      description: `Language specified as "${htmlLang}".`,
      evidence: `<html lang="${htmlLang}">`,
      remediation: 'Ensure language code accurately reflects primary body content.',
    });
  }

  // Check Image Alt attributes
  const allImages = $('img');
  const missingAltImages: string[] = [];
  allImages.each((_, el) => {
    const alt = $(el).attr('alt');
    if (typeof alt === 'undefined') {
      const src = $(el).attr('src') || 'image';
      missingAltImages.push(src.substring(0, 50));
    }
  });
  metrics['Total Images'] = allImages.length;
  metrics['Images Missing Alt'] = missingAltImages.length;

  if (missingAltImages.length > 0) {
    issues.push({
      id: 'a11y-img-alt',
      category: 'accessibility',
      severity: missingAltImages.length > 3 ? 'high' : 'medium',
      title: `${missingAltImages.length} Image(s) Missing alt Attribute`,
      description: `Detected ${missingAltImages.length} <img> element(s) without an alt attribute.`,
      impact: 'Screen reader users receive no context about image content; search engines cannot parse image semantics.',
      remediation: 'Provide descriptive alt text for informative images or `alt=""` for purely decorative images.',
      evidence: missingAltImages.slice(0, 3).join(', ') + (missingAltImages.length > 3 ? '...' : ''),
      domSelector: 'img:not([alt])',
    });
  } else if (allImages.length > 0) {
    issues.push({
      id: 'a11y-img-alt-pass',
      category: 'accessibility',
      severity: 'passed',
      title: 'All Images Contain Alt Attributes',
      description: `All ${allImages.length} images have an alt attribute declared.`,
      remediation: 'Verify alt text provides genuine descriptive value rather than keyword repetition.',
    });
  }

  // Check Heading Hierarchy (H1)
  const h1Count = $('h1').length;
  metrics['H1 Elements Count'] = h1Count;
  if (h1Count === 0) {
    issues.push({
      id: 'a11y-h1-missing',
      category: 'accessibility',
      severity: 'medium',
      title: 'Missing <h1> Primary Heading',
      description: 'No <h1> element was found in the returned HTML. This is a document-structure signal, not by itself proof of an accessibility failure.',
      impact: 'A primary heading can help users, including screen-reader users, understand the page topic and navigate its structure.',
      remediation: 'Add a descriptive top-level heading where it reflects the page content, and verify the complete heading hierarchy.',
    });
  } else if (h1Count > 1) {
    issues.push({
      id: 'a11y-h1-multiple',
      category: 'accessibility',
      severity: 'low',
      title: `Multiple <h1> Headings Detected (${h1Count})`,
      description: `Found ${h1Count} separate <h1> tags on the page.`,
      impact: 'While permitted in HTML5 sectioning, standard convention and assistive technology navigation favor a single top-level <h1> per page.',
      remediation: 'Reserve <h1> for the main page title and structure sub-sections with <h2> and <h3>.',
    });
  } else {
    issues.push({
      id: 'a11y-h1-pass',
      category: 'accessibility',
      severity: 'passed',
      title: 'Proper Single <h1> Document Structure',
      description: 'The page has a clear single <h1> element.',
      evidence: $('h1').first().text().trim().substring(0, 60),
      remediation: 'Maintain logical progression (H1 -> H2 -> H3).',
    });
  }

  // 4. PERFORMANCE & RESOURCE HYGIENE
  const htmlSizeKb = Math.round((new TextEncoder().encode(input.html).byteLength / 1024) * 10) / 10;
  const scriptTags = $('script[src]').length;
  const styleTags = $('link[rel="stylesheet"]').length;
  metrics['Decoded HTML Size'] = `${htmlSizeKb} KB`;
  metrics['External Scripts'] = scriptTags;
  metrics['External Stylesheets'] = styleTags;
  metrics['HTML Fetch Duration'] = `${input.responseTimeMs} ms`;
  metrics['HTTP Status'] = input.statusCode;
  metrics['HTTP Status Class'] = `${Math.floor(input.statusCode / 100)}xx`;

  if (input.responseTimeMs > 2000) {
    issues.push({
      id: 'perf-slow-ttfb',
      category: 'performance',
      severity: 'high',
      title: `Slow Initial HTML Fetch Duration (${input.responseTimeMs}ms)`,
      description: 'The initial HTML request and response-body read took more than 2.0 seconds. This is not a pure time-to-first-byte or browser-rendering measurement.',
      impact: 'A slow initial HTML fetch can delay the start of rendering and may indicate origin, network, or payload-size overhead.',
      remediation: 'Enable edge caching (CDN), server-side caching, or optimize database queries and server compute.',
    });
  } else if (input.responseTimeMs > 800) {
    issues.push({
      id: 'perf-moderate-ttfb',
      category: 'performance',
      severity: 'medium',
      title: `Sub-optimal Initial HTML Fetch Duration (${input.responseTimeMs}ms)`,
      description: 'Initial HTML fetch duration is between 800ms and 2000ms, including reading the response body; it is not a pure time-to-first-byte measurement.',
      remediation: 'Implement HTTP compression (gzip/brotli) and CDN caching.',
    });
  } else {
    issues.push({
      id: 'perf-ttfb-pass',
      category: 'performance',
      severity: 'passed',
      title: `Fast Initial HTML Fetch (${input.responseTimeMs}ms)`,
      description: 'The initial HTML response and body were fetched within the 800ms threshold. This does not measure browser rendering or real-user performance.',
      remediation: 'Maintain CDN and caching layers.',
    });
  }

  if (htmlSizeKb > 500) {
    issues.push({
      id: 'perf-html-bloat',
      category: 'performance',
      severity: 'medium',
      title: `Large Initial HTML Document (${htmlSizeKb} KB)`,
      description: 'The initial HTML payload exceeds 500 KB, indicating large inline blobs, huge state hydration, or base64 data.',
      impact: 'Increases cellular data consumption and delays DOM parsing.',
      remediation: 'Externalize large inline assets, lazy-load heavy subtrees, and enable Brotli/Gzip compression.',
    });
  }

  if (input.statusCode >= 500) {
    issues.push({
      id: 'http-server-error',
      category: 'performance',
      severity: 'critical',
      title: `Server Error Response (HTTP ${input.statusCode})`,
      description: `The target returned HTTP ${input.statusCode}. Auditor inspected the returned error response, which may not represent the intended website page.`,
      impact: 'Visitors and search crawlers may be unable to access the intended page while the server error persists.',
      remediation: 'Investigate the origin or hosting logs, verify upstream dependencies, and repeat the audit after the endpoint returns a successful response.',
      evidence: `HTTP ${input.statusCode}`,
    });
  } else if (input.statusCode >= 400) {
    issues.push({
      id: 'http-client-error',
      category: 'performance',
      severity: 'high',
      title: `Client Error Response (HTTP ${input.statusCode})`,
      description: `The target returned HTTP ${input.statusCode}. SEO and accessibility observations apply to this response body and may not represent the intended page.`,
      impact: 'The requested resource may be missing, blocked, or inaccessible to visitors and search crawlers.',
      remediation: 'Confirm the URL and routing, inspect access controls, and repeat the audit against the intended canonical page.',
      evidence: `HTTP ${input.statusCode}`,
    });
  }

  return { issues, metrics };
}

/**
 * Deterministic source code vulnerability & anti-pattern scanning
 */
export function runCodeDeterministicAudit(input: CodeAuditInput): {
  issues: AuditIssue[];
  metrics: Record<string, string | number | boolean>;
} {
  const issues: AuditIssue[] = [];
  const metrics: Record<string, string | number | boolean> = {};
  const lines = input.code.split('\n');

  metrics['Total Lines of Code'] = lines.length;
  metrics['Language'] = input.language;
  metrics['Filename'] = input.filename;

  // Rule 1: Hardcoded AWS Credentials
  const awsRegex = /(?:AKIA|ASIA)[0-9A-Z]{16}/g;
  lines.forEach((line, idx) => {
    if (awsRegex.test(line)) {
      issues.push({
        id: `code-aws-key-${idx + 1}`,
        category: 'security',
        severity: 'critical',
        title: 'Hardcoded AWS Access Key Detected',
        description: `Potential hardcoded AWS Access Key ID found on line ${idx + 1}.`,
        impact: 'Exposed cloud credentials allow attackers to take over cloud infrastructure, exfiltrate data, or incur massive compute costs.',
        remediation: 'Immediately rotate this key in AWS IAM and store secrets in environment variables (e.g. AWS_ACCESS_KEY_ID) or secret managers (AWS Secrets Manager, Vault).',
        lineNumber: idx + 1,
        evidence: line.trim(),
        codeSnippet: {
          original: line.trim(),
          proposed: '// Load credentials from secure environment\nconst accessKeyId = process.env.AWS_ACCESS_KEY_ID;',
        },
        references: [{ title: 'AWS Best Practices for Managing Access Keys', url: 'https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html' }],
      });
    }
  });

  // Rule 2: Hardcoded Generic API Keys or Passwords
  const secretRegex = /(?:api[_-]?key|secret|password|auth[_-]?token|bearer)\s*[:=]\s*["']([A-Za-z0-9_\-]{16,})["']/i;
  lines.forEach((line, idx) => {
    // avoid false positive if line looks like process.env
    if (!line.includes('process.env') && !line.includes('import') && !line.includes('export type') && secretRegex.test(line)) {
      issues.push({
        id: `code-hardcoded-secret-${idx + 1}`,
        category: 'security',
        severity: 'critical',
        title: 'Hardcoded API Key or Secret Credential',
        description: `Hardcoded secret string detected on line ${idx + 1}.`,
        impact: 'Committing secrets into source control makes them permanently discoverable in git history by malicious actors.',
        remediation: 'Extract credentials into `.env` files or system environment variables and add secret files to `.gitignore`.',
        lineNumber: idx + 1,
        evidence: line.trim(),
        codeSnippet: {
          original: line.trim(),
          proposed: '// Load secret from environment\nconst apiKey = process.env.API_KEY;',
        },
      });
    }
  });

  // Rule 3: SQL Injection Vulnerability (String Concatenation in Queries)
  const sqlConcatRegex = /(?:query|execute|raw|db\.\w+)\s*\(\s*(?:["'`].*?(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER).*?["'`]\s*\+|\s*\`.*?\$\{.*?\}.*?(?:SELECT|INSERT|UPDATE|DELETE))/i;
  lines.forEach((line, idx) => {
    if (sqlConcatRegex.test(line)) {
      issues.push({
        id: `code-sqli-${idx + 1}`,
        category: 'security',
        severity: 'critical',
        title: 'SQL Injection Vulnerability (Concatenated Query)',
        description: `Unsanitized user inputs are interpolated or concatenated directly into a SQL statement on line ${idx + 1}.`,
        impact: 'Enables attackers to bypass authentication, dump database records, or corrupt tables via malicious SQL syntax injection.',
        remediation: 'Use parameterized / prepared statements or an ORM with automatic query parameter escaping (e.g. `db.query("SELECT * FROM users WHERE id = $1", [userId])`).',
        lineNumber: idx + 1,
        evidence: line.trim(),
        codeSnippet: {
          original: line.trim(),
          proposed: '// Use parameterized queries\nconst result = await db.query("SELECT * FROM users WHERE id = $1", [userId]);',
        },
        references: [{ title: 'OWASP SQL Injection Prevention', url: 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html' }],
      });
    }
  });

  // Rule 4: Dangerous Dynamic Code Execution (eval, new Function)
  const evalRegex = /\b(?:eval|Function)\s*\(/;
  lines.forEach((line, idx) => {
    if (evalRegex.test(line) && !line.includes('//')) {
      issues.push({
        id: `code-eval-${idx + 1}`,
        category: 'security',
        severity: 'high',
        title: 'Dangerous Dynamic Code Execution (`eval`)',
        description: `Direct use of \`eval()\` or dynamic \`Function()\` constructor found on line ${idx + 1}.`,
        impact: 'If any portion of the evaluated string contains untrusted user input, it allows arbitrary Remote Code Execution (RCE).',
        remediation: 'Refactor the logic to use typed functions, JSON.parse() for structured data, or safe lookup tables instead of dynamic evaluation.',
        lineNumber: idx + 1,
        evidence: line.trim(),
      });
    }
  });

  // Rule 5: Cross-Site Scripting (XSS) via dangerouslySetInnerHTML or innerHTML
  const xssRegex = /(?:dangerouslySetInnerHTML|innerHTML\s*=)/;
  lines.forEach((line, idx) => {
    if (xssRegex.test(line)) {
      issues.push({
        id: `code-xss-${idx + 1}`,
        category: 'security',
        severity: 'high',
        title: 'Potential Cross-Site Scripting (DOM Injection)',
        description: `Unescaped HTML injection via \`dangerouslySetInnerHTML\` or \`innerHTML\` on line ${idx + 1}.`,
        impact: 'Allows malicious actors to inject client-side JavaScript, steal cookies, or hijack sessions if user input is rendered without sanitization.',
        remediation: 'Sanitize HTML inputs using libraries like DOMPurify or render pure text nodes via standard React children.',
        lineNumber: idx + 1,
        evidence: line.trim(),
        codeSnippet: {
          original: line.trim(),
          proposed: '// Sanitize with DOMPurify before injecting\nimport DOMPurify from "dompurify";\n<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userContent) }} />',
        },
      });
    }
  });

  // Rule 6: Command Injection (child_process.exec with string concat)
  const cmdRegex = /(?:exec|execSync)\s*\(\s*(?:["'`].*?\+|`.*?\$\{)/;
  lines.forEach((line, idx) => {
    if (cmdRegex.test(line)) {
      issues.push({
        id: `code-cmd-inj-${idx + 1}`,
        category: 'security',
        severity: 'critical',
        title: 'Command Injection Risk in System Execution',
        description: `Unsanitized parameters concatenated into child_process \`exec()\` on line ${idx + 1}.`,
        impact: 'Attackers can append shell metacharacters (e.g. `; rm -rf /`, `| cat /etc/passwd`) to execute arbitrary operating system commands.',
        remediation: 'Use `execFile` or `spawn` with an array of arguments instead of spawning a shell with interpolated command strings.',
        lineNumber: idx + 1,
        evidence: line.trim(),
      });
    }
  });

  // Rule 7: Weak Cryptographic Hashing
  const weakCryptoRegex = /(?:createHash\s*\(\s*["'](?:md5|sha1)["']|md5\s*\(|sha1\s*\()/i;
  lines.forEach((line, idx) => {
    if (weakCryptoRegex.test(line)) {
      issues.push({
        id: `code-weak-crypto-${idx + 1}`,
        category: 'quality',
        severity: 'medium',
        title: 'Use of Deprecated/Weak Hashing Algorithm (MD5/SHA1)',
        description: `MD5 or SHA1 hash detected on line ${idx + 1}.`,
        impact: 'These algorithms suffer from known collision vulnerabilities and must never be used for password hashing, digital signatures, or security tokens.',
        remediation: 'Use SHA-256 / SHA-3 for checksums or bcrypt / Argon2 / PBKDF2 for password storage.',
        lineNumber: idx + 1,
        evidence: line.trim(),
      });
    }
  });

  // Rule 8: Silent Error Swallowing
  const emptyCatchRegex = /catch\s*\([^)]*\)\s*\{\s*\}/;
  lines.forEach((line, idx) => {
    if (emptyCatchRegex.test(line)) {
      issues.push({
        id: `code-empty-catch-${idx + 1}`,
        category: 'quality',
        severity: 'low',
        title: 'Empty / Silent Catch Block',
        description: `Exception caught and silently ignored on line ${idx + 1}.`,
        impact: 'Suppresses unexpected runtime faults, complicating debugging and potentially leaving the application in an indeterminate state.',
        remediation: 'Log the error to monitoring telemetry or rethrow with contextual information.',
        lineNumber: idx + 1,
        evidence: line.trim(),
      });
    }
  });

  if (issues.length === 0) {
    issues.push({
      id: 'code-clean-pass',
      category: 'security',
      severity: 'passed',
      title: 'No Common Vulnerability Signatures Found',
      description: 'Static pattern scanning did not detect obvious credentials, SQL concatenation, or dynamic evaluation.',
      remediation: 'Continue adhering to static typing, safe parameter binding, and continuous dependency auditing.',
    });
  }

  return { issues, metrics };
}

/**
 * Compute normalized scores for each category and overall rating
 */
export function calculateAuditScores(issues: AuditIssue[]): {
  overallScore: number;
  categories: Record<Category, CategoryScore>;
} {
  const categories: Category[] = ['security', 'seo', 'accessibility', 'performance', 'quality'];
  const result: Record<Category, CategoryScore> = {
    security: { category: 'security', score: 100, passedCount: 0, totalChecks: 0 },
    seo: { category: 'seo', score: 100, passedCount: 0, totalChecks: 0 },
    accessibility: { category: 'accessibility', score: 100, passedCount: 0, totalChecks: 0 },
    performance: { category: 'performance', score: 100, passedCount: 0, totalChecks: 0 },
    quality: { category: 'quality', score: 100, passedCount: 0, totalChecks: 0 },
  };

  const penaltyMap: Record<string, number> = {
    critical: 25,
    high: 15,
    medium: 8,
    low: 4,
    passed: 0,
  };

  issues.forEach((issue) => {
    const cat = issue.category;
    if (!result[cat]) {
      result[cat] = { category: cat, score: 100, passedCount: 0, totalChecks: 0 };
    }
    result[cat].totalChecks += 1;
    if (issue.severity === 'passed') {
      result[cat].passedCount += 1;
    } else {
      const penalty = penaltyMap[issue.severity] || 5;
      result[cat].score = Math.max(0, result[cat].score - penalty);
    }
  });

  // Calculate overall weighted average
  let totalScore = 0;
  let activeCategories = 0;
  categories.forEach((cat) => {
    if (result[cat].totalChecks > 0) {
      totalScore += result[cat].score;
      activeCategories += 1;
    }
  });

  const overallScore = activeCategories > 0 ? Math.round(totalScore / activeCategories) : 100;
  return { overallScore, categories: result };
}
