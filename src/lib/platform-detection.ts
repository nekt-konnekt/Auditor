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
