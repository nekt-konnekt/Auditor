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
      severity: 'high',
      title: 'Insecure HTTP Transport Protocol',
      description: 'The submitted URL uses plaintext HTTP, so this request is not protected by TLS. This observation describes transport security; it does not establish what data the site handles or whether a specific attack is exploitable.',
      impact: 'Traffic can be read or modified by an on-path attacker. The practical impact depends on the content and functionality served; sensitive forms, sessions, or data should not be sent over HTTP.',
      remediation: 'For a conventional public website, configure HTTPS and redirect HTTP requests to HTTPS. Some narrowly scoped services intentionally use HTTP for captive-portal detection; document that exception and do not send sensitive data over that endpoint.',
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
  const weakCspPattern = /(?:^|;)\s*(?:script-src|default-src)\s+[^;]*(?:'unsafe-inline'|'unsafe-eval'|\*)/i;
  metrics['CSP Present'] = !!csp;
  if (!csp) {
    issues.push({
      id: 'sec-csp',
      category: 'security',
      severity: 'medium',
      title: 'Missing Content-Security-Policy (CSP) Header',
      description: 'No Content-Security-Policy header was observed in this response. CSP is a defense-in-depth control; its absence alone does not establish that an XSS vulnerability exists.',
      impact: 'Without CSP, the browser has fewer policy-based restrictions if a separate injection flaw is present.',
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
      title: 'Content-Security-Policy Header Present',
      description: 'A CSP header was observed and this simple heuristic did not match broad script/default-source patterns. This is not a full policy validator or proof that the policy is effective.',
      evidence: csp.substring(0, 80) + (csp.length > 80 ? '...' : ''),
      remediation: 'Ensure directives are restrictive and avoid "unsafe-inline" where possible.',
    });
  }

  // Check 3: Strict-Transport-Security (HSTS)
  const hsts = headers['strict-transport-security'];
  const hstsMaxAge = hsts?.match(/(?:^|;)\s*max-age\s*=\s*(\d+)/i);
  const hstsEffective = Boolean(hstsMaxAge && Number(hstsMaxAge[1]) > 0);
  // Browsers ignore HSTS received over HTTP, so evaluate effectiveness only
  // on HTTPS responses. A present header with max-age=0 disables HSTS.
  metrics['HSTS Present'] = isHttps ? hstsEffective : 'Not applicable (HTTP)';
  if (isHttps && !hstsEffective) {
    issues.push({
      id: 'sec-hsts',
      category: 'security',
      severity: 'medium',
      title: hsts ? 'Ineffective Strict-Transport-Security (HSTS) Header' : 'Missing Strict-Transport-Security (HSTS) Header',
      description: hsts
        ? 'The HSTS header is present but does not contain a positive max-age directive, so browsers may not retain an HTTPS-only policy.'
        : 'No Strict-Transport-Security header was observed on this HTTPS response.',
      impact: 'Without an effective HSTS policy, browsers may be less protected against downgrade attempts after an initial HTTP visit.',
      evidence: hsts || 'Header missing from response headers.',
      remediation: 'After confirming HTTPS is supported across the intended host scope, configure a positive max-age value and carefully consider includeSubDomains or preload.',
    });
  } else if (isHttps) {
    issues.push({
      id: 'sec-hsts-pass',
      category: 'security',
      severity: 'passed',
      title: 'HSTS Header Has a Positive max-age',
      description: 'The HTTPS response includes a Strict-Transport-Security header with a positive max-age. Scope and preload readiness were not fully evaluated.',
      evidence: hsts,
      remediation: 'Review host/subdomain scope and preload requirements separately.',
    });
  }

  // Check 4: X-Frame-Options
  const xfo = headers['x-frame-options'];
  const validXfo = Boolean(xfo && /^(DENY|SAMEORIGIN)$/i.test(xfo.trim()));
  const frameAncestorsDirective = csp?.split(';').map((part) => part.trim())
    .find((part) => /^frame-ancestors\s+\S+/i.test(part));
  const hasFrameProtection = validXfo || Boolean(frameAncestorsDirective);
  metrics['X-Frame-Options'] = xfo || 'Not set';
  if (!hasFrameProtection) {
    issues.push({
      id: 'sec-xfo',
      category: 'security',
      severity: 'medium',
      title: 'Clickjacking Protection Missing (X-Frame-Options)',
      description: 'No valid X-Frame-Options value (DENY or SAMEORIGIN) or non-empty CSP frame-ancestors directive was observed.',
      impact: 'If the page is frameable and sensitive interactions are present, embedding may enable clickjacking. This header check does not demonstrate an exploitable clickjacking flow.',
      remediation: "Set X-Frame-Options to SAMEORIGIN or DENY, or specify a suitable frame-ancestors directive in CSP.",
      evidence: xfo || 'No valid frame protection header observed.',
    });
  } else {
    issues.push({
      id: 'sec-xfo-pass',
      category: 'security',
      severity: 'passed',
      title: 'Valid Frame Embedding Restriction Detected',
      description: 'A supported X-Frame-Options value or non-empty CSP frame-ancestors directive was observed.',
      evidence: validXfo ? xfo : 'Protected via CSP frame-ancestors',
      remediation: 'Verify that frame restrictions match the intended embedding policy.',
    });
  }

  // Check 5: X-Content-Type-Options
  const xcto = headers['x-content-type-options'];
  metrics['X-Content-Type-Options'] = xcto || 'Not set';
  if (!xcto || xcto.trim().toLowerCase() !== 'nosniff') {
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
      severity: 'medium',
      title: 'Missing <title> Element',
      description: 'No title element was found in the fetched HTML response. Browser-rendered or other-route content was not inspected.',
      impact: 'Browsers and search engines may have less descriptive information for this page; this observation does not establish a specific ranking penalty.',
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
      title: 'Page Title Present and Within Configured Length Range',
      description: 'A title element is present and contains ' + title.length + ' characters; this check does not assess relevance, uniqueness, or search-engine display.',
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
      severity: 'medium',
      title: 'Missing Meta Description',
      description: 'No meta description was found in the fetched HTML response.',
      impact: 'Search engines may generate their own snippets; a missing description does not by itself prove a ranking or click-through penalty.',
      remediation: 'Consider adding a concise, page-specific description that accurately summarizes the content. Search engines may still choose a different snippet.',
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
      title: 'Meta Description Present and Within Configured Length Range',
      description: 'A meta description is present and contains ' + metaDesc.length + ' characters; this check does not assess its accuracy, uniqueness, or likely search performance.',
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
      severity: 'medium',
      title: 'Missing Viewport Meta Tag',
      description: 'No viewport meta tag was found in the fetched HTML response.',
      impact: 'The absence may affect mobile layout behavior, but browser rendering was not tested in this audit.',
      remediation: 'Add a viewport declaration appropriate for the page, commonly <meta name="viewport" content="width=device-width, initial-scale=1">.',
    });
  } else {
    issues.push({
      id: 'seo-viewport-pass',
      category: 'seo',
      severity: 'passed',
      title: 'Viewport Meta Tag Present',
      description: 'A viewport meta tag was observed. This check does not validate its settings or confirm responsive rendering.',
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
      title: 'Single H1 Element Detected',
      description: 'Exactly one h1 element was found in the fetched HTML; heading hierarchy and visual presentation were not evaluated.',
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
  metrics['Browser Runtime Checks'] = 'Not performed';
  metrics['Route Coverage'] = 'Submitted URL only';
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
  const awsRegex = /(?:AKIA|ASIA)[0-9A-Z]{16}/;
  lines.forEach((line, idx) => {
    if (awsRegex.test(line)) {
      issues.push({
        id: `code-aws-key-${idx + 1}`,
        category: 'security',
        severity: 'high',
        title: 'Potential Hardcoded AWS Access Key ID',
        description: `An AWS key-shaped identifier was found on line ${idx + 1}. Static pattern matching cannot determine whether it is a real credential, active, or a placeholder.`, 
        impact: 'If this is a valid or previously exposed credential, it may enable unauthorized access to AWS resources. Validity and permissions were not checked.',
        remediation: 'Verify whether the value is a real credential. If valid or exposed, revoke or rotate it and review cloud access logs; store replacement credentials in a secret manager.',
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
        severity: 'high',
        title: 'Potential Hardcoded Credential-Like Value',
        description: `A string matching a credential-like assignment pattern was found on line ${idx + 1}. It may be a real secret, test value, or placeholder; validity was not checked.`, 
        impact: 'If the value is a live credential and is committed to source control, it may be exposed through repository access or history.',
        remediation: 'Verify whether the value is a real secret. If it is live or exposed, revoke or rotate it and remove it from active code; remember that deleting a line does not erase Git history.',
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
        severity: 'medium',
        title: 'Potential SQL Injection Risk from Query Construction',
        description: `SQL-like query string concatenation or interpolation was detected on line ${idx + 1}. This pattern alone does not prove that attacker-controlled input reaches the query.`, 
        impact: 'If untrusted input reaches the constructed query without safe parameterization, an attacker may alter the intended SQL operation.',
        remediation: 'Trace the values used to build the query and use parameterized/prepared statements for untrusted values. Confirm the actual query API and data flow before classifying this as a confirmed vulnerability.',
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
        severity: 'medium',
        title: 'Dynamic Code Execution Requires Context Review',
        description: `Use of \`eval()\` or the dynamic \`Function()\` constructor was detected on line ${idx + 1}. Its presence alone does not establish that untrusted input is evaluated.`, 
        impact: 'If attacker-controlled content reaches dynamic evaluation, it may enable code execution in the current execution context.',
        remediation: 'Trace the evaluated value to its source. Avoid dynamic evaluation where possible; if required, ensure untrusted input cannot reach it.',
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
        severity: 'medium',
        title: 'Potential HTML Injection Sink Requires Context Review',
        description: `An HTML injection sink (\`dangerouslySetInnerHTML\` or \`innerHTML\`) was detected on line ${idx + 1}. This does not prove that untrusted input reaches the sink or that sanitization is absent.`, 
        impact: 'If attacker-controlled HTML reaches the sink without effective sanitization, it may enable cross-site scripting or other DOM injection.',
        remediation: 'Trace the value supplied to the sink. Prefer rendering text; when HTML is required, use a suitable sanitizer and verify that sanitization cannot be bypassed.',
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
        severity: 'medium',
        title: 'Potential Command Injection Risk',
        description: `Shell command construction with concatenation or interpolation was detected on line ${idx + 1}. The pattern alone does not establish that attacker-controlled input reaches the command.`, 
        impact: 'If untrusted input is interpolated into a shell command, an attacker may execute unintended operating-system commands.',
        remediation: 'Trace command arguments to their sources. Prefer `execFile` or `spawn` with argument arrays and avoid invoking a shell with untrusted interpolated values.',
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
        title: 'MD5/SHA-1 Use Requires Context Review',
        description: `MD5 or SHA-1 usage was detected on line ${idx + 1}. Suitability depends on the purpose; collision resistance is inadequate for security-sensitive uses.`, 
        impact: 'Do not use MD5 or SHA-1 for password storage, digital signatures, or security tokens. Some non-security legacy checksum uses have different requirements.',
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
