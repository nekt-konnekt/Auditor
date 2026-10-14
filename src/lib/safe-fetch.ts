import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { createBrotliDecompress, createGunzip, createInflate } from 'node:zlib';

const MAX_REDIRECTS = 5;
const MAX_BODY_BYTES = 2 * 1024 * 1024;

export interface ResolvedPublicTarget {
  url: URL;
  address: string;
  family: 4 | 6;
}

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
  // Permit only global-unicast space and exclude known special-purpose ranges.
  if (!value.startsWith('2') && !value.startsWith('3')) return true;
  if (/^2001:db8:/i.test(value)) return true;
  if (/^2001:0{1,4}:/i.test(value)) return true; // Teredo/special protocol assignments
  if (/^2002:/i.test(value)) return true; // 6to4 embeds an IPv4 destination
  if (/^64:ff9b:/i.test(value)) return true; // NAT64 well-known prefix may embed IPv4 destinations
  return false;
}

function isPublicAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return !isBlockedIpv4(address);
  if (family === 6) return !isBlockedIpv6(address);
  return false;
}

async function resolvePublicHttpTarget(input: string): Promise<ResolvedPublicTarget> {
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
  let address: string;
  let addressFamily: 4 | 6;

  if (family === 4 || family === 6) {
    if (!isPublicAddress(hostname)) throw new Error('Local and private network targets are not allowed.');
    address = hostname;
    addressFamily = family;
  } else {
    let records: Array<{ address: string; family: number }>;
    try {
      records = await lookup(hostname, { all: true, verbatim: true });
    } catch {
      throw new Error('The target hostname could not be resolved.');
    }
    if (!records.length || records.some((record) => !isPublicAddress(record.address))) {
      throw new Error('The target resolves to a local or non-public network address and cannot be audited.');
    }
    // Railway's current production configuration has IPv6 egress disabled.
    // Prefer an already-validated IPv4 answer when available, then pin it.
    const selected = records.find((record) => record.family === 4) || records[0];
    address = selected.address;
    addressFamily = selected.family as 4 | 6;
  }

  url.hash = '';
  return { url, address, family: addressFamily };
}

export async function validatePublicHttpUrl(input: string): Promise<URL> {
  return (await resolvePublicHttpTarget(input)).url;
}

/** Resolve and validate a redirect destination, returning the exact address to connect to. */
export async function resolvePublicRedirect(location: string, current: URL): Promise<ResolvedPublicTarget> {
  let destination: URL;
  try {
    destination = new URL(location, current);
  } catch {
    throw new Error('The target returned an invalid redirect destination.');
  }
  return resolvePublicHttpTarget(destination.toString());
}

function toWebHeaders(source: Record<string, string | string[] | undefined>): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(source)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) value.forEach((entry) => headers.append(name, entry));
    else headers.set(name, value);
  }
  // These hop-by-hop headers describe the original socket, not the buffered Response.
  for (const name of ['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade']) {
    headers.delete(name);
  }
  return headers;
}

/**
 * Make the outbound connection to the already-validated IP address. The URL
 * hostname is retained for the HTTP Host header and TLS certificate/SNI checks,
 * while the custom lookup callback prevents a second DNS resolution from
 * changing the destination between validation and connection.
 */
export async function requestPinnedPublicResponse(target: ResolvedPublicTarget, timeoutMs = 12_000): Promise<Response> {
  return new Promise<Response>((resolve, reject) => {
    let settled = false;
    let request: any;
    let timeout: ReturnType<typeof setTimeout>;

    const fail = (error: unknown) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      request?.destroy();
      reject(error);
    };

    const urlHostname = target.url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    const requestOptions: Record<string, unknown> = {
      method: 'GET',
      headers: {
        'User-Agent': 'Auditor-Engine/1.0 (+website audit; contact: security@auditor.invalid)',
        Accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
      },
      lookup: (_hostname: string, options: any, callback: any) => {
        if (options && typeof options === 'object' && options.all) {
          callback(null, [{ address: target.address, family: target.family }]);
        } else {
          callback(null, target.address, target.family);
        }
      },
    };
    if (!isIP(urlHostname)) requestOptions.servername = urlHostname;

    try {
      const client = target.url.protocol === 'https:' ? httpsRequest : httpRequest;
      request = client(target.url, requestOptions as any, (incoming) => {
        const status = incoming.statusCode || 0;
        const headers = toWebHeaders(incoming.headers);
        const isRedirect = [301, 302, 303, 307, 308].includes(status);

        if (isRedirect || [204, 205, 304].includes(status)) {
          settled = true;
          clearTimeout(timeout);
          incoming.destroy();
          resolve(new Response(null, { status, headers }));
          return;
        }

        const contentType = headers.get('content-type') || '';
        if (!contentType.toLowerCase().includes('text/html') && !contentType.toLowerCase().includes('application/xhtml+xml')) {
          fail(new Error('The target did not return an HTML page that Auditor can inspect.'));
          incoming.destroy();
          return;
        }

        const declaredLength = Number(headers.get('content-length') || 0);
        if (declaredLength > MAX_BODY_BYTES) {
          fail(new Error('The target page is larger than the 2 MB audit limit.'));
          incoming.destroy();
          return;
        }

        const encodings = (headers.get('content-encoding') || '')
          .split(',')
          .map((encoding) => encoding.trim().toLowerCase())
          .filter(Boolean)
          .reverse();
        let bodyStream: any = incoming;
        let decoded = false;
        for (const encoding of encodings) {
          if (encoding === 'identity') continue;
          if (encoding === 'gzip' || encoding === 'x-gzip') bodyStream = bodyStream.pipe(createGunzip());
          else if (encoding === 'deflate') bodyStream = bodyStream.pipe(createInflate());
          else if (encoding === 'br') bodyStream = bodyStream.pipe(createBrotliDecompress());
          else {
            fail(new Error('The target uses a content encoding Auditor cannot decode.'));
            incoming.destroy();
            return;
          }
          decoded = true;
        }

        const chunks: Buffer[] = [];
        let total = 0;
        bodyStream.on('data', (chunk: Buffer | Uint8Array) => {
          if (settled) return;
          const buffer = Buffer.from(chunk);
          total += buffer.byteLength;
          if (total > MAX_BODY_BYTES) {
            fail(new Error('The target page is larger than the 2 MB audit limit.'));
            incoming.destroy();
            bodyStream.destroy?.();
            return;
          }
          chunks.push(buffer);
        });
        bodyStream.on('end', () => {
          if (settled) return;
          if (!decoded && declaredLength > 0 && total !== declaredLength) {
            fail(new Error('The target response ended before its declared content length.'));
            return;
          }
          if (decoded) {
            headers.delete('content-encoding');
            headers.delete('content-length');
          }
          settled = true;
          clearTimeout(timeout);
          try {
            resolve(new Response(Buffer.concat(chunks), { status, headers }));
          } catch (error) {
            reject(error);
          }
        });
        bodyStream.on('error', fail);
        incoming.on('error', fail);
      });

      request.on('error', (error: unknown) => fail(error));
      timeout = setTimeout(() => {
        const error = new Error('The target website timed out.');
        (error as Error & { code?: string }).code = 'AUDITOR_TIMEOUT';
        fail(error);
      }, timeoutMs);
      request.end();
    } catch (error) {
      fail(error);
    }
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

function mapRequestError(error: unknown): Error {
  const value = typeof error === 'object' && error !== null ? error as { code?: string; cause?: { code?: string }; message?: string } : {};
  const code = value.code || value.cause?.code;
  if (code === 'AUDITOR_TIMEOUT') return new Error('The target website timed out.');
  if (value.message?.startsWith('The target page is larger than')
    || value.message?.startsWith('The target did not return an HTML page')
    || value.message?.startsWith('The target uses a content encoding')
    || value.message?.startsWith('The target response ended before')) {
    return new Error(value.message);
  }
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') return new Error('The target hostname could not be resolved.');
  if (code === 'CERT_HAS_EXPIRED' || code === 'DEPTH_ZERO_SELF_SIGNED_CERT'
    || code === 'ERR_TLS_CERT_ALTNAME_INVALID' || code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE') {
    return new Error('The target TLS certificate could not be validated.');
  }
  if (code === 'ECONNREFUSED' || code === 'ECONNRESET'
    || code === 'EHOSTUNREACH' || code === 'ENETUNREACH') {
    return new Error('The target server refused or reset the connection, or the network route is unavailable.');
  }
  return new Error('The target website could not be reached due to a network or TLS connection failure.');
}

export async function fetchPublicPage(input: string, timeoutMs = 12_000): Promise<{ url: URL; response: Response; html: string }> {
  let current = await resolvePublicHttpTarget(input);

  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects += 1) {
    let response: Response;
    try {
      response = await requestPinnedPublicResponse(current, timeoutMs);
    } catch (error) {
      throw mapRequestError(error);
    }

    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('location');
      if (!location) throw new Error('The target returned a redirect without a destination.');
      if (redirects === MAX_REDIRECTS) throw new Error('The target redirected too many times.');
      current = await resolvePublicRedirect(location, current.url);
      continue;
    }

    const contentType = response.headers.get('content-type') || '';
    if (!contentType.toLowerCase().includes('text/html') && !contentType.toLowerCase().includes('application/xhtml+xml')) {
      await response.body?.cancel();
      throw new Error('The target did not return an HTML page that Auditor can inspect.');
    }

    const html = await readLimitedText(response);
    return { url: current.url, response, html };
  }

  throw new Error('The target redirected too many times.');
}
