import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { gzipSync } from 'node:zlib';
import type { AddressInfo } from 'node:net';
import test from 'node:test';
import { requestPinnedPublicResponse, resolvePublicRedirect, validatePublicHttpUrl } from '../src/lib/safe-fetch.ts';

async function startServer(handler: (request: IncomingMessage, response: ServerResponse) => void): Promise<{ server: Server; port: number }> {
  const server = createServer(handler);
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const address = server.address() as AddressInfo;
  return { server, port: address.port };
}

async function stopServer(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}

test('rejects local, private, link-local, documentation, and reserved IPv4 targets', async () => {
  const targets = [
    'http://127.0.0.1/',
    'http://10.0.0.1/',
    'http://172.16.0.1/',
    'http://192.168.1.1/',
    'http://169.254.169.254/',
    'http://100.64.0.1/',
    'http://192.0.2.1/',
    'http://203.0.113.4/',
    'http://240.0.0.1/',
  ];
  for (const target of targets) {
    await assert.rejects(validatePublicHttpUrl(target), /Local and private network targets are not allowed/);
  }
});

test('rejects local and non-global IPv6 targets', async () => {
  for (const target of ['http://[::1]/', 'http://[fd00::1]/', 'http://[fe80::1]/', 'http://[::ffff:127.0.0.1]/', 'http://[2001:0000:4136:e378:8000:63bf:3fff:fdd2]/', 'http://[2002:c000:0201::]/', 'http://[64:ff9b::a00:1]/']) {
    await assert.rejects(validatePublicHttpUrl(target), /Local and private network targets are not allowed/);
  }
});

test('rejects localhost aliases, local domains, unsupported protocols, and URL credentials', async () => {
  await assert.rejects(validatePublicHttpUrl('http://localhost/'), /Local and private network targets/);
  await assert.rejects(validatePublicHttpUrl('http://app.localhost/'), /Local and private network targets/);
  await assert.rejects(validatePublicHttpUrl('http://printer.local/'), /Local and private network targets/);
  await assert.rejects(validatePublicHttpUrl('file:///etc/passwd'), /Only HTTP and HTTPS/);
  await assert.rejects(validatePublicHttpUrl('https://user:password@example.com/'), /usernames or passwords/);
});

test('accepts a public IP literal and removes URL fragments', async () => {
  const url = await validatePublicHttpUrl('https://8.8.8.8/path#fragment');
  assert.equal(url.hostname, '8.8.8.8');
  assert.equal(url.hash, '');
});

test('redirect destinations are resolved and validated before they can be requested', async () => {
  await assert.rejects(
    resolvePublicRedirect('http://127.0.0.1/admin', new URL('http://example.com/start')),
    /Local and private network targets/,
  );
  await assert.rejects(
    resolvePublicRedirect('http://169.254.169.254/latest/meta-data', new URL('http://example.com/start')),
    /Local and private network targets/,
  );
});

test('outbound requests use the validated IP while preserving the original Host header', async () => {
  const { server, port } = await startServer((request, response) => {
    response.setHeader('x-test-host', request.headers.host || '');
    response.setHeader('content-type', 'text/html; charset=utf-8');
    response.end('<html><title>Pinned</title></html>');
  });
  try {
    const response = await requestPinnedPublicResponse({
      url: new URL('http://example.com:' + port + '/page'),
      address: '127.0.0.1',
      family: 4,
    }, 1000);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('x-test-host'), 'example.com:' + port);
    assert.equal(await response.text(), '<html><title>Pinned</title></html>');
  } finally {
    await stopServer(server);
  }
});


test('compressed HTML responses are decoded before analysis', async () => {
  const html = '<html><title>Compressed</title></html>';
  const compressed = gzipSync(Buffer.from(html));
  const { server, port } = await startServer((_request, response) => {
    response.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'content-encoding': 'gzip',
      'content-length': String(compressed.byteLength),
    });
    response.end(compressed);
  });
  try {
    const response = await requestPinnedPublicResponse({
      url: new URL('http://example.com:' + port + '/compressed'),
      address: '127.0.0.1',
      family: 4,
    }, 1000);
    assert.equal(await response.text(), html);
    assert.equal(response.headers.get('content-encoding'), null);
    assert.equal(response.headers.get('content-length'), null);
  } finally {
    await stopServer(server);
  }
});

test('decoded response bodies remain subject to the 2 MB size limit', async () => {
  const { server, port } = await startServer((_request, response) => {
    response.writeHead(200, {
      'content-type': 'text/html',
      'content-length': String(2 * 1024 * 1024 + 1),
    });
    response.end('small body');
  });
  try {
    await assert.rejects(
      requestPinnedPublicResponse({
        url: new URL('http://example.com:' + port + '/large'),
        address: '127.0.0.1',
        family: 4,
      }, 1000),
      /larger than the 2 MB audit limit/,
    );
  } finally {
    await stopServer(server);
  }
});

test('request timeout covers a server that never completes the response', async () => {
  const { server, port } = await startServer(() => {
    // Intentionally keep the socket open until the client times out.
  });
  try {
    await assert.rejects(
      requestPinnedPublicResponse({
        url: new URL('http://example.com:' + port + '/slow'),
        address: '127.0.0.1',
        family: 4,
      }, 50),
      /timed out/i,
    );
  } finally {
    await stopServer(server);
  }
});
