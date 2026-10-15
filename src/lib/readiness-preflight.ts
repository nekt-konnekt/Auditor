import tls from 'node:tls';
import { isIP } from 'node:net';
import { getDomain } from 'tldts';
import { createPinnedDnsLookup, getValidatedPublicAddresses } from './safe-fetch.ts';
import { AuditIssue } from '../types/audit.ts';

export const CERT_NEAR_EXPIRY_DAYS = 30;
export const DOMAIN_NEAR_EXPIRY_DAYS = 30;
const TLS_TIMEOUT_MS = 5_000;
const RDAP_TIMEOUT_MS = 5_000;

export interface ReadinessPreflight {
  issues: AuditIssue[];
  metrics: Record<string, string | number | boolean>;
  tlsValid: boolean | null;
}

export function getRegistrableDomain(hostname: string): string {
  const normalized = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  return getDomain(normalized, { allowPrivateDomains: false }) || normalized;
}

function daysUntil(dateValue: string | number | Date): number | null {
  const timestamp = new Date(dateValue).getTime();
  if (!Number.isFinite(timestamp)) return null;
  return Math.ceil((timestamp - Date.now()) / 86_400_000);
}

async function readCertificate(url: URL): Promise<{
  valid: boolean;
  expiresAt: string;
  issuer: string;
  daysRemaining: number;
} | null> {
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  let addresses: Awaited<ReturnType<typeof getValidatedPublicAddresses>>;
  try {
    addresses = await getValidatedPublicAddresses(url.toString());
  } catch {
    return null;
  }
  if (!addresses.length) return null;
  const port = Number(url.port || 443);
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value: ReturnType<typeof readCertificate> extends Promise<infer T> ? T : never) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    const socket = tls.connect({
      host: hostname,
      port,
      ...(isIP(hostname) ? {} : { servername: hostname }),
      lookup: createPinnedDnsLookup(addresses),
      rejectUnauthorized: false,
      timeout: TLS_TIMEOUT_MS,
    });
    socket.once('secureConnect', () => {
      const certificate = socket.getPeerCertificate();
      const validFrom = Date.parse(certificate.valid_from || '');
      const validTo = Date.parse(certificate.valid_to || '');
      if (!certificate || !certificate.valid_to || !Number.isFinite(validTo)) {
        finish(null);
        socket.end();
        return;
      }
      const now = Date.now();
      const dateValid = Number.isFinite(validFrom) && validFrom <= now && validTo > now;
      const daysRemaining = Math.ceil((validTo - now) / 86_400_000);
      finish({
        valid: socket.authorized && dateValid,
        expiresAt: new Date(validTo).toISOString(),
        issuer: (Array.isArray(certificate.issuer?.O) ? certificate.issuer?.O[0] : certificate.issuer?.O) || (Array.isArray(certificate.issuer?.CN) ? certificate.issuer?.CN[0] : certificate.issuer?.CN) || 'Unknown issuer',
        daysRemaining,
      });
      socket.end();
    });
    socket.once('error', () => finish(null));
    socket.once('timeout', () => {
      socket.destroy();
      finish(null);
    });
  });
}

async function readDomainRegistration(domain: string): Promise<{ expiry: string; registrar: string } | null> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), RDAP_TIMEOUT_MS);
  try {
    const response = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: { Accept: 'application/rdap+json, application/json' },
      signal: controller.signal,
    });
    if (!response.ok) return null;
    const data = await response.json() as {
      events?: Array<{ eventAction?: string; eventDate?: string }>;
      entities?: Array<{ roles?: string[]; vcardArray?: unknown[] }>;
    };
    const expiryEvent = data.events?.find((event) => /expiration|expiry/i.test(event.eventAction || ''));
    if (!expiryEvent?.eventDate) return null;
    const registrarEntity = data.entities?.find((entity) => entity.roles?.includes('registrar'));
    const registrar = registrarEntity ? JSON.stringify(registrarEntity.vcardArray || []) : 'Not disclosed by RDAP';
    return { expiry: expiryEvent.eventDate, registrar };
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Read-only preflight. TLS certificate metadata is read with a separate TLS
 * connection; page content is never fetched with certificate verification disabled.
 */
export async function inspectReadinessPreflight(url: URL): Promise<ReadinessPreflight> {
  const issues: AuditIssue[] = [];
  const metrics: Record<string, string | number | boolean> = {};
  let tlsValid: boolean | null = null;
  const domain = getRegistrableDomain(url.hostname);
  const registrationPromise = readDomainRegistration(domain);

  if (url.protocol !== 'https:') {
    tlsValid = false;
    issues.push({
      id: 'tls-https-missing',
      category: 'security',
      severity: 'critical',
      readinessBlocker: true,
      title: 'HTTPS/TLS Not Enabled',
      description: 'The target uses plaintext HTTP, so transport encryption and certificate validity cannot be verified.',
      remediation: 'Configure a valid TLS certificate and redirect HTTP traffic to HTTPS.',
    });
  } else {
    const certificate = await readCertificate(url);
    if (!certificate) {
      metrics['TLS Certificate Status'] = 'Could not determine';
      issues.push({
        id: 'tls-certificate-unknown',
        category: 'security',
        severity: 'medium',
        title: 'TLS Certificate Could Not Be Verified',
        description: 'Auditor could not retrieve certificate metadata within the read-only probe timeout. This is not a pass.',
        remediation: 'Verify the host is reachable on port 443 and that its TLS endpoint presents a certificate.',
      });
    } else {
      tlsValid = certificate.valid;
      metrics['TLS Certificate Expires'] = certificate.expiresAt;
      metrics['TLS Certificate Days Remaining'] = certificate.daysRemaining;
      metrics['TLS Certificate Issuer'] = certificate.issuer;
      if (certificate.daysRemaining <= 0 || !certificate.valid) {
        issues.push({
          id: 'tls-certificate-invalid',
          category: 'security',
          severity: 'critical',
          readinessBlocker: true,
          title: certificate.daysRemaining <= 0 ? 'TLS Certificate Expired' : 'TLS Certificate Chain or Validity Failed',
          description: `The certificate metadata indicates an invalid or expired TLS certificate. Expiry: ${certificate.expiresAt}; issuer: ${certificate.issuer}.`,
          evidence: `Days remaining: ${certificate.daysRemaining}`,
          remediation: 'Install or renew a certificate whose hostname, validity dates, and trust chain validate successfully.',
        });
      } else if (certificate.daysRemaining <= CERT_NEAR_EXPIRY_DAYS) {
        issues.push({
          id: 'tls-certificate-near-expiry',
          category: 'security',
          severity: 'high',
          title: 'TLS Certificate Near Expiry',
          description: `The TLS certificate expires in ${certificate.daysRemaining} day(s), on ${certificate.expiresAt}.`,
          evidence: `Issuer: ${certificate.issuer}`,
          remediation: 'Renew the certificate and verify automatic renewal before the expiry date.',
        });
      } else {
        issues.push({
          id: 'tls-certificate-pass',
          category: 'security',
          severity: 'passed',
          title: 'TLS Certificate Valid',
          description: `The TLS certificate is currently valid and expires in ${certificate.daysRemaining} day(s).`,
          evidence: `Issuer: ${certificate.issuer}; expires: ${certificate.expiresAt}`,
          remediation: 'Keep automatic certificate renewal enabled and monitor expiry.',
        });
      }
    }
  }

  const registration = await registrationPromise;
  if (!registration) {
    metrics['Domain Expiry Status'] = 'Could not determine';
    issues.push({
      id: 'domain-expiry-unknown',
      category: 'quality',
      severity: 'low',
      title: 'Domain Expiry Could Not Be Determined',
      description: 'The RDAP registry did not return a usable domain-expiry event. Auditor does not treat missing registration data as a pass.',
      remediation: 'Check the registrar directly and confirm the domain auto-renewal and payment details.',
    });
  } else {
    const daysRemaining = daysUntil(registration.expiry);
    metrics['Domain Expires'] = registration.expiry;
    metrics['Domain Expiry Days Remaining'] = daysRemaining ?? 'Could not determine';
    if (daysRemaining === null) {
      issues.push({
        id: 'domain-expiry-unknown',
        category: 'quality',
        severity: 'low',
        title: 'Domain Expiry Could Not Be Determined',
        description: 'RDAP returned an unparseable domain-expiry date.',
        remediation: 'Check the registrar directly and confirm auto-renewal.',
      });
    } else if (daysRemaining <= 0) {
      issues.push({
        id: 'domain-expired',
        category: 'security',
        severity: 'critical',
        readinessBlocker: true,
        title: 'Domain Registration Expired',
        description: `RDAP reports the domain registration expiry as ${registration.expiry}.`,
        remediation: 'Renew the domain through its registrar immediately and verify that the registration is active.',
      });
    } else if (daysRemaining <= DOMAIN_NEAR_EXPIRY_DAYS) {
      issues.push({
        id: 'domain-near-expiry',
        category: 'quality',
        severity: 'high',
        title: 'Domain Registration Near Expiry',
        description: `RDAP reports that the domain expires in ${daysRemaining} day(s).`,
        remediation: 'Renew the domain and verify auto-renewal and billing details with the registrar.',
      });
    } else {
      issues.push({
        id: 'domain-expiry-pass',
        category: 'quality',
        severity: 'passed',
        title: 'Domain Registration Not Near Expiry',
        description: `RDAP reports ${daysRemaining} day(s) until domain expiry.`,
        remediation: 'Keep registrar contact and renewal details current.',
      });
    }
  }

  return { issues, metrics, tlsValid };
}
