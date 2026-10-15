import { load } from 'cheerio';
import { fetchPublicPage, fetchPublicResource } from './safe-fetch.ts';

export const MAX_ADDITIONAL_ROUTES = 3;
const STATIC_ASSET = /\.(?:avif|bmp|css|csv|gif|ico|jpe?g|js|json|map|pdf|png|svg|txt|webp|woff2?|zip)$/i;

export interface CrawledRoute {
  url: URL;
  statusCode: number;
  headers: Record<string, string>;
  html: string;
  responseTimeMs: number;
}

export function parseRobotsDisallowRules(robotsText: string): string[] {
  const rules: string[] = [];
  let agents: string[] = [];
  let groupHasDirectives = false;
  for (const rawLine of robotsText.split(/\r?\n/)) {
    const line = rawLine.split('#', 1)[0].trim();
    if (!line) continue;
    const separator = line.indexOf(':');
    if (separator < 0) continue;
    const directive = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    if (directive === 'user-agent') {
      if (groupHasDirectives) {
        agents = [];
        groupHasDirectives = false;
      }
      agents.push(value.toLowerCase());
      continue;
    }
    if (directive === 'allow' || directive === 'disallow' || directive === 'crawl-delay' || directive === 'sitemap') {
      groupHasDirectives = true;
    }
    if (directive === 'disallow' && agents.includes('*') && value.startsWith('/')) {
      rules.push(value);
    }
  }
  return [...new Set(rules)];
}

function isDisallowed(pathname: string, rules: string[]): boolean {
  return rules.some((rule) => rule.endsWith('*')
    ? pathname.startsWith(rule.slice(0, -1))
    : pathname.startsWith(rule));
}

export async function discoverAdditionalRoutes(
  homepageUrl: URL,
  homepageHtml: string,
  maxRoutes = MAX_ADDITIONAL_ROUTES,
): Promise<URL[]> {
  const boundedLimit = Math.max(0, Math.min(MAX_ADDITIONAL_ROUTES, Math.floor(maxRoutes)));
  if (boundedLimit === 0) return [];

  // Robots is fetched as a same-origin, size-limited resource. If it cannot be
  // read reliably, do not expand the crawl beyond the submitted page.
  let robots: Awaited<ReturnType<typeof fetchPublicResource>> = null;
  try {
    // No redirects here: the route crawl has a strict four-request expansion budget.
    robots = await fetchPublicResource(new URL('/robots.txt', homepageUrl).toString(), homepageUrl.origin, 6_000, 0);
  } catch {
    return [];
  }
  if (!robots || (robots.status >= 500) || (robots.status >= 200 && robots.status < 300 && !robots.contentType.toLowerCase().includes('text/plain') && robots.body.length === 0)) {
    return [];
  }
  const disallowRules = robots.status >= 200 && robots.status < 300
    ? parseRobotsDisallowRules(robots.body)
    : [];

  const $ = load(homepageHtml);
  const discovered: URL[] = [];
  const seen = new Set<string>([homepageUrl.toString()]);
  $('a[href]').each((_index, element) => {
    if (discovered.length >= boundedLimit) return;
    const href = $(element).attr('href');
    if (!href) return;
    try {
      const candidate = new URL(href, homepageUrl);
      candidate.hash = '';
      if (candidate.origin !== homepageUrl.origin || candidate.username || candidate.password) return;
      if (candidate.protocol !== 'http:' && candidate.protocol !== 'https:') return;
      if (candidate.search || STATIC_ASSET.test(candidate.pathname)) return;
      if (!candidate.pathname.startsWith('/')) return;
      if (seen.has(candidate.toString()) || isDisallowed(candidate.pathname, disallowRules)) return;
      seen.add(candidate.toString());
      discovered.push(candidate);
    } catch {
      // Ignore malformed links without failing the primary audit.
    }
  });
  return discovered;
}

export async function crawlAdditionalRoutes(homepageUrl: URL, homepageHtml: string): Promise<{
  routes: CrawledRoute[];
  attempted: number;
  skippedByRobots: number;
}> {
  const candidates = await discoverAdditionalRoutes(homepageUrl, homepageHtml);
  const routes: CrawledRoute[] = [];
  let attempted = 0;
  for (const candidate of candidates) {
    attempted += 1;
    const start = Date.now();
    try {
      const { url, response, html } = await fetchPublicPage(candidate.toString(), 8_000, 0);
      const headers: Record<string, string> = {};
      response.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });
      routes.push({ url, statusCode: response.status, headers, html, responseTimeMs: Date.now() - start });
    } catch {
      // One inaccessible route must not fail the submitted site's audit.
    }
  }
  return { routes, attempted, skippedByRobots: 0 };
}
