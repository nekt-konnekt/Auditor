import { lookup } from 'node:dns/promises';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { isIP } from 'node:net';

const MAX_REDIRECTS = 5;
const MAX_BODY_BYTES = 2 * 1024 * 1024;

function ipv4ToNumber(address: string): number {
  return address.split('.').reduce((value, part) => ((value << 8) | Number(part)) >>> 0, 0);
}

function inIpv4Range(address: string, base: string, bits: number): boolean {
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipv4ToNumber(address) & mask) === (ipv4ToNumber(base) & mask);
}

function isBlockedIpv4(address: string): boolean {
  const blocked: Array<[string, number]> = [
    ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10],
    ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
    ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16],
    ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
    ['224.0.0.0', 4], ['240.0.0.0', 4],
  ];
  return blocked.some(([base, bits]) => inIpv4Range(address, base, bits));
}

function isBlockedIpv6(address: string): boolean {
  const value = address.toLowerCase().split('%')[0];
  if (value === '::' || value === '::1' || value.startsWith('::ffff:')) return true;
  // Permit only globally-routable unicast space (2000::/3); exclude documentation space.
  if (!value.startsWith('2') && !value.startsWith('3')) return true;
  if (/^2001:db8:/i.test(value)) return true;
  return false;
}

function isPublicAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return !isBlockedIpv4(address);
  if (family === 6) return !isBlockedIpv6(address);
  return false;
}

/**
 * Validate every DNS answer before requesting a target. Redirects are handled
 * manually so each hop receives the same validation.
 */
export type ValidatedPublicAddress = { address: string; family: number };

async function validatePublicHttpUrlWithAddresses(input: string): Promise<{ url: URL; addresses: ValidatedPublicAddress[] }> {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new Error('Enter a valid website URL.');
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('Only HTTP and HTTPS website URLs are supported.');
  }
  if (url.username || url.password) {
    throw new Error('URLs containing usernames or passwords are not allowed.');
  }
  if (!url.hostname || url.hostname === 'localhost' || url.hostname.endsWith('.localhost') || url.hostname.endsWith('.local')) {
    throw new Error('Local and private network targets are not allowed.');
  }

  const hostname = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  const family = isIP(hostname);
  let addresses: ValidatedPublicAddress[];
  if (family) {
    if (!isPublicAddress(hostname)) throw new Error('Local and private network targets are not allowed.');
    addresses = [{ address: hostname, family }];
  } else {
    let records;
    try {
      records = await lookup(hostname, { all: true, verbatim: true });
    } catch {
      throw new Error('The target hostname could not be resolved.');
    }
    if (!records.length || records.some((record) => !isPublicAddress(record.address))) {
      throw new Error('The target resolves to a local or non-public network address and cannot be audited.');
    }
    addresses = records.map((record) => ({ address: record.address, family: record.family }));
  }

  url.hash = '';
  return { url, addresses };
}

export async function validatePublicHttpUrl(input: string): Promise<URL> {
  return (await validatePublicHttpUrlWithAddresses(input)).url;
}

export async function getValidatedPublicAddresses(input: string): Promise<ValidatedPublicAddress[]> {
  return (await validatePublicHttpUrlWithAddresses(input)).addresses;
}

export function createPinnedDnsLookup(addresses: ValidatedPublicAddress[]): any {
  return ((_hostname: string, options: { all?: boolean } | number, callback: (...args: any[]) => void) => {
    if (typeof options === 'object' && options?.all) callback(null, addresses);
    else callback(null, addresses[0].address, addresses[0].family);
  }) as any;
}

/** Make the request using only the DNS addresses already validated above. */
function requestPublicResponse(
  url: URL,
  addresses: ValidatedPublicAddress[],
  timeoutMs: number,
  maxBodyBytes: number,
  headers: Record<string, string>,
): Promise<Response> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const fail = (error: Error) => {
      if (settled) return;
      settled = true;
      reject(error);
    };
    const requestOptions: Record<string, unknown> = {
      method: 'GET',
      headers,
      lookup: createPinnedDnsLookup(addresses),
    };
    const hostname = url.hostname.replace(/^\[|\]$/g, '');
    if (url.protocol === 'https:' && !isIP(hostname)) requestOptions.servername = hostname;

    const transport = url.protocol === 'https:' ? httpsRequest : httpRequest;
    const request = transport(url, requestOptions as never, (incoming) => {
      const declaredLength = Number(incoming.headers['content-length'] || 0);
      if (declaredLength > maxBodyBytes) {
        incoming.destroy();
        fail(new Error(maxBodyBytes === MAX_BODY_BYTES
          ? 'The target page is larger than the 2 MB audit limit.'
          : 'The target resource is larger than the 1 MB audit limit.'));
        return;
      }

      const chunks: Buffer[] = [];
      let total = 0;
      incoming.on('data', (chunk: Buffer | string) => {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        total += buffer.byteLength;
        if (total > maxBodyBytes) {
          incoming.destroy();
          request.destroy();
          fail(new Error(maxBodyBytes === MAX_BODY_BYTES
            ? 'The target page is larger than the 2 MB audit limit.'
            : 'The target resource is larger than the 1 MB audit limit.'));
          return;
        }
        chunks.push(buffer);
      });
      incoming.once('error', (error) => fail(error));
      incoming.once('end', () => {
        if (settled) return;
        const responseHeaders = new Headers();
        for (const [key, value] of Object.entries(incoming.headers)) {
          if (value !== undefined) responseHeaders.set(key, Array.isArray(value) ? value.join(', ') : String(value));
        }
        settled = true;
        const status = incoming.statusCode || 502;
        const body = [204, 205, 304].includes(status) ? null : Buffer.concat(chunks);
        resolve(new Response(body, { status, headers: responseHeaders }));
      });
    });
    request.setTimeout(timeoutMs, () => request.destroy(new Error('The target website timed out.')));
    request.once('error', (error) => fail(error));
    request.end();
  });
}

async function readLimitedText(response: Response): Promise<string> {
  const declaredLength = Number(response.headers.get('content-length') || 0);
  if (declaredLength > MAX_BODY_BYTES) {
    await response.body?.cancel();
    throw new Error('The target page is larger than the 2 MB audit limit.');
  }
  if (!response.body) return '';

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BODY_BYTES) {
        await reader.cancel();
        throw new Error('The target page is larger than the 2 MB audit limit.');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(combined);
}

export async function fetchPublicPage(input: string, timeoutMs = 12_000, maxRedirects = MAX_REDIRECTS): Promise<{ url: URL; response: Response; html: string }> {
  let validated = await validatePublicHttpUrlWithAddresses(input);
  let current = validated.url;
  let addresses = validated.addresses;

  for (let redirects = 0; redirects <= maxRedirects; redirects += 1) {
    let response: Response;
    try {
      response = await requestPublicResponse(current, addresses, timeoutMs, MAX_BODY_BYTES, {
        'User-Agent': 'Auditor-Engine/1.0 (+website audit; contact: security@auditor.invalid)',
        Accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.5',
      });
    } catch (error) {
      if (error instanceof Error && /audit limit|timed out/.test(error.message)) throw error;
      const causeCode = typeof error === 'object' && error !== null && 'code' in error
        ? (error as { code?: string }).code
        : typeof error === 'object' && error !== null && 'cause' in error
          ? (error as { cause?: { code?: string } }).cause?.code
          : undefined;
      if (causeCode === 'ENOTFOUND' || causeCode === 'EAI_AGAIN') {
        throw new Error('The target hostname could not be resolved.');
      }
      if (causeCode === 'CERT_HAS_EXPIRED' || causeCode === 'DEPTH_ZERO_SELF_SIGNED_CERT'
        || causeCode === 'ERR_TLS_CERT_ALTNAME_INVALID' || causeCode === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE') {
        throw new Error('The target TLS certificate could not be validated.');
      }
      if (causeCode === 'ECONNREFUSED' || causeCode === 'ECONNRESET'
        || causeCode === 'EHOSTUNREACH' || causeCode === 'ENETUNREACH') {
        throw new Error('The target server refused or reset the connection, or the network route is unavailable.');
      }
      throw new Error('The target website could not be reached due to a network or TLS connection failure.');
    }

    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('location');
      await response.body?.cancel();
      if (!location) throw new Error('The target returned a redirect without a destination.');
      if (redirects === maxRedirects) throw new Error('The target redirected too many times.');
      validated = await validatePublicHttpUrlWithAddresses(new URL(location, current).toString());
      current = validated.url;
      addresses = validated.addresses;
      continue;
    }

    const contentType = response.headers.get('content-type') || '';
    if (!contentType.toLowerCase().includes('text/html') && !contentType.toLowerCase().includes('application/xhtml+xml')) {
      await response.body?.cancel();
      throw new Error('The target did not return an HTML page that Auditor can inspect.');
    }

    const html = await readLimitedText(response);
    return { url: current, response, html };
  }

  throw new Error('The target redirected too many times.');
}


const MAX_RESOURCE_BYTES = 1_000_000;
const RESOURCE_MAX_REDIRECTS = 3;

/** Fetch a small public same-origin resource for passive exposure checks. */
export async function fetchPublicResource(input: string, expectedOrigin: string, timeoutMs = 6_000, maxRedirects = RESOURCE_MAX_REDIRECTS): Promise<{ url: URL; status: number; contentType: string; body: string } | null> {
  let validated: { url: URL; addresses: ValidatedPublicAddress[] };
  try {
    validated = await validatePublicHttpUrlWithAddresses(input);
  } catch {
    return null;
  }
  let current = validated.url;
  let addresses = validated.addresses;

  for (let redirects = 0; redirects <= maxRedirects; redirects += 1) {
    if (current.origin !== expectedOrigin) return null;
    let response: Response;
    try {
      response = await requestPublicResponse(current, addresses, timeoutMs, MAX_RESOURCE_BYTES, {
        'User-Agent': 'Auditor-Engine/1.0 (+passive public-page audit)',
        Accept: 'text/plain,application/json,application/javascript,text/javascript,*/*;q=0.2',
      });
    } catch {
      return null;
    }

    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('location');
      await response.body?.cancel();
      if (!location || redirects === maxRedirects) return null;
      try {
        validated = await validatePublicHttpUrlWithAddresses(new URL(location, current).toString());
      } catch {
        return null;
      }
      current = validated.url;
      addresses = validated.addresses;
      if (current.origin !== expectedOrigin) return null;
      continue;
    }
    if (!response.ok) {
      await response.body?.cancel();
      return { url: current, status: response.status, contentType: response.headers.get('content-type') || '', body: '' };
    }

    return {
      url: current,
      status: response.status,
      contentType: response.headers.get('content-type') || '',
      body: await response.text(),
    };
  }
  return null;
}
