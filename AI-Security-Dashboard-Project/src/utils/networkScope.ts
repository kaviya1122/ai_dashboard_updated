/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export interface NetworkScopeVerification {
  isValidIpOrCidr: boolean;
  ip: string;
  cidrMask?: number;
  scopeType: 'private_rfc1918' | 'loopback' | 'authorized_lab' | 'unauthorized_public';
  isAuthorized: boolean;
  message: string;
}

// Authorized lab CIDR ranges (RFC 5737 documentation test blocks and designated internal ranges)
const AUTHORIZED_LAB_PREFIXES = ['198.51.100.', '203.0.113.', '192.0.2.'];

/**
 * Checks if an IPv4 address belongs to private RFC 1918 or Loopback addresses
 */
export function checkNetworkScope(target: string, userHasExplicitConsent: boolean): NetworkScopeVerification {
  const trimmed = target.trim();
  if (!trimmed) {
    return {
      isValidIpOrCidr: false,
      ip: '',
      scopeType: 'unauthorized_public',
      isAuthorized: false,
      message: 'Network target cannot be empty. Specify an authorized IPv4 address or CIDR.',
    };
  }

  // Parse IP and optional CIDR mask (e.g. 192.168.1.1 or 10.0.0.0/24)
  const parts = trimmed.split('/');
  const ip = parts[0].trim();
  let cidrMask: number | undefined;

  if (parts.length > 1) {
    const parsedMask = parseInt(parts[1], 10);
    if (isNaN(parsedMask) || parsedMask < 8 || parsedMask > 32) {
      return {
        isValidIpOrCidr: false,
        ip,
        scopeType: 'unauthorized_public',
        isAuthorized: false,
        message: 'Invalid CIDR mask. Mask must be between /8 and /32.',
      };
    }
    cidrMask = parsedMask;
  }

  // Validate IPv4 format
  const octets = ip.split('.');
  if (octets.length !== 4) {
    return {
      isValidIpOrCidr: false,
      ip,
      scopeType: 'unauthorized_public',
      isAuthorized: false,
      message: 'Invalid IPv4 address. Must contain exactly 4 octets (e.g., 192.168.1.50).',
    };
  }

  for (const octet of octets) {
    const num = Number(octet);
    if (!/^\d+$/.test(octet) || isNaN(num) || num < 0 || num > 255) {
      return {
        isValidIpOrCidr: false,
        ip,
        scopeType: 'unauthorized_public',
        isAuthorized: false,
        message: `Invalid octet "${octet}". Value must be between 0 and 255.`,
      };
    }
  }

  const first = Number(octets[0]);
  const second = Number(octets[1]);

  // Determine Scope
  let scopeType: 'private_rfc1918' | 'loopback' | 'authorized_lab' | 'unauthorized_public' = 'unauthorized_public';

  if (first === 127) {
    scopeType = 'loopback';
  } else if (
    first === 10 ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168)
  ) {
    scopeType = 'private_rfc1918';
  } else if (AUTHORIZED_LAB_PREFIXES.some((prefix) => ip.startsWith(prefix))) {
    scopeType = 'authorized_lab';
  }

  // Public IP Scanning Guardrail:
  // Scanning public targets without written legal authorization is strictly prohibited.
  if (scopeType === 'unauthorized_public') {
    return {
      isValidIpOrCidr: true,
      ip,
      cidrMask,
      scopeType,
      isAuthorized: false,
      message: 'Scope violation: Public Internet IP scanning is disabled by safety guardrails. Analysis is restricted to verified RFC1918 internal subnets, localhost, or authorized sandbox labs (198.51.100.0/24).',
    };
  }

  if (!userHasExplicitConsent) {
    return {
      isValidIpOrCidr: true,
      ip,
      cidrMask,
      scopeType,
      isAuthorized: false,
      message: 'Authorization required: You must confirm that you have explicit permission from the asset owner to inspect this internal target.',
    };
  }

  return {
    isValidIpOrCidr: true,
    ip,
    cidrMask,
    scopeType,
    isAuthorized: true,
    message: `Target validated within authorized ${scopeType.replace('_', ' ').toUpperCase()} scope.`,
  };
}

/**
 * Deterministic port & service vulnerability analysis for authorized target
 */
export interface PortInspectionResult {
  port: number;
  service: string;
  state: 'open' | 'filtered' | 'closed';
  riskContribution: number;
  riskReason?: string;
  cveAssociations?: string[];
}

export function inspectAuthorizedPorts(openPorts: number[]): {
  totalRisk: number;
  findings: PortInspectionResult[];
  recommendations: string[];
} {
  const findings: PortInspectionResult[] = [];
  const recommendations: string[] = [];
  let totalRisk = 0;

  const portRiskMap: Record<number, { service: string; risk: number; reason: string; cve: string[] }> = {
    21: { service: 'FTP', risk: 25, reason: 'Plaintext protocol susceptible to credential sniffing.', cve: ['CVE-2020-15778'] },
    23: { service: 'Telnet', risk: 40, reason: 'Legacy unencrypted terminal communication. High exploit surface.', cve: ['CVE-2020-10188'] },
    80: { service: 'HTTP', risk: 10, reason: 'Unencrypted web traffic. Enforce TLS 1.3 / HTTPS.', cve: [] },
    445: { service: 'SMB / NetBIOS', risk: 45, reason: 'High-risk vector for lateral movement (EternalBlue/WannaCry vector).', cve: ['CVE-2017-0144', 'CVE-2020-0796'] },
    3389: { service: 'RDP', risk: 35, reason: 'Remote Desktop protocol exposed. Common brute force target (BlueKeep vector).', cve: ['CVE-2019-0708'] },
    4444: { service: 'Metasploit Listener', risk: 50, reason: 'Default Metasploit payload reverse handler port.', cve: ['SIG-MAL-METASPLOIT'] },
    8080: { service: 'HTTP-Alt / Proxy', risk: 15, reason: 'Alternative web service or management interface.', cve: [] },
  };

  for (const port of openPorts) {
    const known = portRiskMap[port];
    if (known) {
      findings.push({
        port,
        service: known.service,
        state: 'open',
        riskContribution: known.risk,
        riskReason: known.reason,
        cveAssociations: known.cve,
      });
      totalRisk += known.risk;
      recommendations.push(`Port ${port} (${known.service}): ${known.reason}`);
    } else {
      findings.push({
        port,
        service: `Service-${port}`,
        state: 'open',
        riskContribution: 5,
        riskReason: 'Non-standard port detected open.',
      });
      totalRisk += 5;
    }
  }

  return {
    totalRisk: Math.min(100, totalRisk),
    findings,
    recommendations,
  };
}
