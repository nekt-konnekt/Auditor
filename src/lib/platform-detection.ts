export interface PlatformSignals {
  platforms: string[];
  evidence: string[];
}

export function detectPlatform(headers: Record<string, string>, html: string): PlatformSignals {
  const normalizedHeaders = Object.fromEntries(
    Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value.toLowerCase()])
  );
  const source = html.toLowerCase();
  const found = new Set<string>();
  const evidence: string[] = [];

  const add = (name: string, reason: string) => {
    found.add(name);
    evidence.push(reason);
  };

  if (normalizedHeaders['x-powered-by']?.includes('next.js') || source.includes('/_next/static/')) add('Next.js', 'Next.js response header or static asset path');
  if (source.includes('wp-content/') || source.includes('wp-includes/') || normalizedHeaders['x-pingback']) add('WordPress', 'WordPress asset path or pingback header');
  if (source.includes('cdn.shopify.com') || source.includes('shopify.theme')) add('Shopify', 'Shopify asset reference');
  if (source.includes('webflow.io') || source.includes('website-files.com')) add('Webflow', 'Webflow asset or hosted-site reference');
  if (source.includes('wixstatic.com') || source.includes('wix.com/')) add('Wix', 'Wix asset reference');
  if (source.includes('squarespace.com') || source.includes('static1.squarespace.com')) add('Squarespace', 'Squarespace asset reference');
  if (source.includes('drupal.settings') || source.includes('/sites/default/files/')) add('Drupal', 'Drupal runtime or public asset path');
  if (source.includes('joomla') || source.includes('/media/system/js/')) add('Joomla', 'Joomla runtime or asset path');
  if (source.includes('data-reactroot') || source.includes('react-dom')) add('React', 'React runtime marker');
  if (source.includes('__vue__') || source.includes('data-v-')) add('Vue', 'Vue runtime marker');
  if (normalizedHeaders['server']?.includes('cloudflare') || normalizedHeaders['cf-ray']) add('Cloudflare', 'Cloudflare response header');
  if (normalizedHeaders['x-vercel-id'] || normalizedHeaders['server']?.includes('vercel')) add('Vercel', 'Vercel response header');
  if (normalizedHeaders['x-nf-request-id']) add('Netlify', 'Netlify response header');
  if (normalizedHeaders['server']?.includes('nginx')) add('Nginx', 'Nginx server header');
  if (normalizedHeaders['server']?.includes('apache')) add('Apache', 'Apache server header');

  return { platforms: [...found], evidence: [...new Set(evidence)] };
}

const PLATFORM_GUIDANCE: Record<string, string> = {
  'Next.js': 'Keep credentials and privileged API calls server-side; review server/client component boundaries, deployment environment variables, caching, and response security headers.',
  WordPress: 'Update WordPress core, themes, and plugins; remove unused extensions; enforce least-privilege accounts; and verify backups and file permissions.',
  Shopify: 'Review third-party app permissions and theme code; keep private credentials out of storefront JavaScript and custom liquid templates.',
  Webflow: 'Review custom code embeds and connected forms; keep private integration keys server-side and verify third-party script permissions.',
  Wix: 'Review custom code and app permissions; keep private keys in server-side integrations and minimize third-party script access.',
  Squarespace: 'Review code injection and connected extensions; never place private credentials in browser-delivered scripts.',
  Drupal: 'Patch Drupal core and contributed modules; review roles, file permissions, and public file exposure.',
  Joomla: 'Patch Joomla core and extensions; review administrator accounts, extension permissions, and public file exposure.',
  React: 'Treat every bundled value as public; move credentials server-side and apply a restrictive Content Security Policy.',
  Vue: 'Treat every bundled value as public; move credentials server-side and review exposed build-time environment variables.',
  Cloudflare: 'Use WAF rules and rate limiting where appropriate; restrict origin access and verify TLS and security headers at both edge and origin.',
  Vercel: 'Keep secrets in server-only environment variables; review preview deployment protection, serverless function access, and response headers.',
  Netlify: 'Keep secrets out of client build variables; review deploy previews, function permissions, and response security headers.',
  Nginx: 'Verify TLS configuration, security headers, access controls, and that directory listing and sensitive paths are disabled.',
  Apache: 'Verify TLS configuration, security headers, access controls, and that directory listing and sensitive paths are disabled.',
};

export function getPlatformGuidance(platforms: string[]): string[] {
  return platforms.map((platform) => PLATFORM_GUIDANCE[platform]).filter((guidance): guidance is string => Boolean(guidance));
}
