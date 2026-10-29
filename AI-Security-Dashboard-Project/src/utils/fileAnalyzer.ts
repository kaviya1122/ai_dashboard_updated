/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export interface SafetyDeduction {
  category: string;
  pointsDeducted: number;
  reason: string;
}

export interface UniversalFileAnalysis {
  fileName: string;
  fileSizeBytes: number;
  fileSizeFormatted: string;
  mimeType: string;
  detectedFormat: 'csv' | 'json' | 'log' | 'pcap' | 'binary' | 'archive' | 'image' | 'generic';
  sha256Hash: string;
  entropy: number; // 0 to 8 (Shannon entropy; >7.2 indicates packed/encrypted/ransomware)
  entropyAssessment: 'normal' | 'compressed' | 'high_entropy_packed' | 'encrypted_ransomware';
  gcpStorageUri: string;
  gcpBucket: string;
  storageClass: 'STANDARD' | 'NEARLINE' | 'ARCHIVE';
  extractedIocs: {
    ips: string[];
    domains: string[];
    hashes: string[];
    cves: string[];
    emails: string[];
  };
  samplePreview: string;
  structuredDetails?: Record<string, unknown>;
  threatSignaturesMatched: string[];

  // Percentage safety metrics (0% to 100% safe)
  safetyPercentage: number;
  safetyVerdict: 'safe' | 'suspicious' | 'malicious';
  safetyVerdictLabel: string;
  isSafe: boolean;
  safetyDeductions: SafetyDeduction[];
}

/**
 * Calculates Shannon entropy of a byte array (0.0 to 8.0)
 */
export function calculateShannonEntropy(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0;

  const frequencies = new Array(256).fill(0);
  for (let i = 0; i < bytes.length; i++) {
    frequencies[bytes[i]]++;
  }

  let entropy = 0;
  const len = bytes.length;

  for (let i = 0; i < 256; i++) {
    if (frequencies[i] > 0) {
      const p = frequencies[i] / len;
      entropy -= p * Math.log2(p);
    }
  }

  return Math.round(entropy * 1000) / 1000;
}

/**
 * Formats byte size into human readable string up to 100MB+
 */
export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Detects format category from file name, extension, and content
 */
export function detectFileCategory(fileName: string, mime: string): UniversalFileAnalysis['detectedFormat'] {
  const lower = fileName.toLowerCase();

  if (lower.endsWith('.csv') || lower.endsWith('.tsv') || mime.includes('csv')) {
    return 'csv';
  }
  if (lower.endsWith('.json') || lower.endsWith('.jsonl') || lower.endsWith('.ndjson') || mime.includes('json')) {
    return 'json';
  }
  if (lower.endsWith('.log') || lower.endsWith('.txt') || lower.endsWith('.syslog') || lower.endsWith('.evtx')) {
    return 'log';
  }
  if (lower.endsWith('.pcap') || lower.endsWith('.pcapng') || lower.endsWith('.cap')) {
    return 'pcap';
  }
  if (lower.endsWith('.exe') || lower.endsWith('.dll') || lower.endsWith('.bin') || lower.endsWith('.elf') || lower.endsWith('.sh') || lower.endsWith('.ps1')) {
    return 'binary';
  }
  if (lower.endsWith('.zip') || lower.endsWith('.tar.gz') || lower.endsWith('.tgz') || lower.endsWith('.7z') || lower.endsWith('.rar')) {
    return 'archive';
  }
  if (lower.endsWith('.png') || lower.endsWith('.jpg') || lower.endsWith('.jpeg') || lower.endsWith('.gif') || lower.endsWith('.webp')) {
    return 'image';
  }

  return 'generic';
}

/**
 * Extracts IOCs (IPs, domains, hashes, CVEs, emails) from plain text strings
 */
export function extractIocsFromContent(text: string): UniversalFileAnalysis['extractedIocs'] {
  const ips = new Set<string>();
  const domains = new Set<string>();
  const hashes = new Set<string>();
  const cves = new Set<string>();
  const emails = new Set<string>();

  // IPv4 regex (excluding 0.0.0.0 and 255.255.255.255)
  const ipMatches = text.match(/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g);
  if (ipMatches) {
    ipMatches.forEach((ip) => {
      if (!ip.startsWith('0.') && !ip.startsWith('255.')) {
        ips.add(ip);
      }
    });
  }

  // CVE pattern
  const cveMatches = text.match(/\bCVE-\d{4}-\d{4,7}\b/gi);
  if (cveMatches) {
    cveMatches.forEach((cve) => cves.add(cve.toUpperCase()));
  }

  // SHA256 hashes
  const sha256Matches = text.match(/\b[a-fA-F0-9]{64}\b/g);
  if (sha256Matches) {
    sha256Matches.forEach((h) => hashes.add(h.toLowerCase()));
  }

  // MD5 hashes
  const md5Matches = text.match(/\b[a-fA-F0-9]{32}\b/g);
  if (md5Matches) {
    md5Matches.slice(0, 10).forEach((h) => hashes.add(h.toLowerCase()));
  }

  // Emails
  const emailMatches = text.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b/g);
  if (emailMatches) {
    emailMatches.forEach((em) => emails.add(em.toLowerCase()));
  }

  // Domains
  const domainMatches = text.match(/\b[a-zA-Z0-9][-a-zA-Z0-9]{1,62}\.(?:com|org|net|io|ru|cn|cc|xyz|top|biz|edu|gov)\b/gi);
  if (domainMatches) {
    domainMatches.forEach((d) => {
      const dom = d.toLowerCase();
      if (!dom.includes('example.com') && !ips.has(dom)) {
        domains.add(dom);
      }
    });
  }

  return {
    ips: Array.from(ips).slice(0, 50),
    domains: Array.from(domains).slice(0, 50),
    hashes: Array.from(hashes).slice(0, 30),
    cves: Array.from(cves).slice(0, 20),
    emails: Array.from(emails).slice(0, 20),
  };
}

/**
 * Universal security inspector for ANY uploaded file up to 100MB
 */
export function analyzeAnySecurityFile(params: {
  fileName: string;
  fileSizeBytes: number;
  mimeType?: string;
  rawBytes?: Uint8Array;
  textSnippet?: string;
  sha256?: string;
}): UniversalFileAnalysis {
  const { fileName, fileSizeBytes, mimeType = 'application/octet-stream', rawBytes, textSnippet = '', sha256 } = params;

  // Max 100MB limit
  const maxLimit = 100 * 1024 * 1024;
  if (fileSizeBytes > maxLimit) {
    throw new Error(`File size (${formatBytes(fileSizeBytes)}) exceeds maximum authorized ceiling of 100MB.`);
  }

  const detectedFormat = detectFileCategory(fileName, mimeType);

  // Compute or estimate entropy
  let entropy = 4.5;
  if (rawBytes && rawBytes.length > 0) {
    entropy = calculateShannonEntropy(rawBytes);
  } else if (textSnippet) {
    const encoder = new TextEncoder();
    entropy = calculateShannonEntropy(encoder.encode(textSnippet.slice(0, 8192)));
  } else if (detectedFormat === 'archive' || detectedFormat === 'binary') {
    entropy = 7.42; // typical binary/compressed
  }

  let entropyAssessment: UniversalFileAnalysis['entropyAssessment'] = 'normal';
  if (entropy > 7.6) {
    entropyAssessment = 'encrypted_ransomware';
  } else if (entropy > 7.1) {
    entropyAssessment = 'high_entropy_packed';
  } else if (entropy > 6.0) {
    entropyAssessment = 'compressed';
  }

  // Extract IOCs from whatever text snippet is available
  const extractedIocs = extractIocsFromContent(textSnippet || fileName);

  // Threat signatures
  const threatSignaturesMatched: string[] = [];
  if (entropyAssessment === 'encrypted_ransomware' || entropyAssessment === 'high_entropy_packed') {
    threatSignaturesMatched.push('SIG-ENTROPY-OUTFIT: High-entropy payload indicating packing, obfuscation, or encryption');
  }
  if (extractedIocs.cves.length > 0) {
    threatSignaturesMatched.push(`SIG-CVE-REF: Contains explicit CVE exploit references (${extractedIocs.cves.join(', ')})`);
  }
  if (detectedFormat === 'binary' && (fileName.endsWith('.exe') || fileName.endsWith('.dll'))) {
    threatSignaturesMatched.push('SIG-BINARY-PE: Portable Executable format flagged for dynamic sandbox containment');
  }
  if (textSnippet.includes('powershell') || textSnippet.includes('base64')) {
    threatSignaturesMatched.push('SIG-SCRIPT-STAGING: Script interpreter invocations or base64 decoding utilities detected');
  }

  // File Safety Percentage Calculation (0% to 100% Safe)
  const safetyDeductions: SafetyDeduction[] = [];
  let score = 100;

  // Deduct for Entropy / Ransomware
  if (entropyAssessment === 'encrypted_ransomware') {
    score -= 40;
    safetyDeductions.push({
      category: 'High Entropy & Encryption',
      pointsDeducted: 40,
      reason: 'Shannon entropy exceeds 7.6, indicating encrypted payload or ransomware obfuscation',
    });
  } else if (entropyAssessment === 'high_entropy_packed') {
    score -= 25;
    safetyDeductions.push({
      category: 'Packed Binary Code',
      pointsDeducted: 25,
      reason: 'Elevated entropy (>7.1) suggests packed or compressed executable sections',
    });
  }

  // Deduct for CVE Exploit references
  if (extractedIocs.cves.length > 0) {
    const penalty = Math.min(50, extractedIocs.cves.length * 25);
    score -= penalty;
    safetyDeductions.push({
      category: 'Known CVE Exploits',
      pointsDeducted: penalty,
      reason: `File contains explicit CVE vulnerability signatures (${extractedIocs.cves.join(', ')})`,
    });
  }

  // Deduct for dangerous executable/binary format
  if (detectedFormat === 'binary' || fileName.toLowerCase().endsWith('.exe') || fileName.toLowerCase().endsWith('.dll')) {
    score -= 25;
    safetyDeductions.push({
      category: 'Executable Binary File',
      pointsDeducted: 25,
      reason: 'PE executable or library binary flagged for dynamic sandbox containment',
    });
  }

  // Deduct for suspicious script commands (PowerShell, base64 stager)
  const lowerSnippet = (textSnippet || '').toLowerCase();
  if (lowerSnippet.includes('powershell') || lowerSnippet.includes('-enc') || lowerSnippet.includes('base64') || fileName.toLowerCase().endsWith('.ps1')) {
    score -= 30;
    safetyDeductions.push({
      category: 'Malicious Script Staging',
      pointsDeducted: 30,
      reason: 'Encoded PowerShell command or stager dropper patterns identified',
    });
  }

  // Deduct for beaconing / C2 indicators
  if (lowerSnippet.includes('beacon') || lowerSnippet.includes('c2') || lowerSnippet.includes('heartbeat') || lowerSnippet.includes('cobalt')) {
    score -= 30;
    safetyDeductions.push({
      category: 'C2 Command & Control',
      pointsDeducted: 30,
      reason: 'Command and control communication traces or beaconing telemetry observed',
    });
  }

  // Deduct for brute force or credential dumping
  if (lowerSnippet.includes('failed password') || lowerSnippet.includes('lsass') || lowerSnippet.includes('brute') || lowerSnippet.includes('spray')) {
    score -= 25;
    safetyDeductions.push({
      category: 'Credential Attack Telemetry',
      pointsDeducted: 25,
      reason: 'Authentication brute-force attempts or LSASS memory scraping patterns detected',
    });
  }

  // Clamp safety percentage between 0% and 100%
  const safetyPercentage = Math.max(0, Math.min(100, score));

  let safetyVerdict: UniversalFileAnalysis['safetyVerdict'] = 'safe';
  let safetyVerdictLabel = `${safetyPercentage}% heuristic score — No high-risk markers found`;

  if (safetyPercentage < 50) {
    safetyVerdict = 'malicious';
    safetyVerdictLabel = `${safetyPercentage}% heuristic score — Possible high-risk markers found`;
  } else if (safetyPercentage < 80) {
    safetyVerdict = 'suspicious';
    safetyVerdictLabel = `${safetyPercentage}% heuristic score — Review recommended`;
  }

  // This analyzer runs in the browser; no cloud storage is configured.
  const gcpBucket = '';
  const gcpStorageUri = 'Not uploaded — analysis is local to this browser session';

  return {
    fileName,
    fileSizeBytes,
    fileSizeFormatted: formatBytes(fileSizeBytes),
    mimeType,
    detectedFormat,
    sha256Hash: sha256 || `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`,
    entropy,
    entropyAssessment,
    gcpStorageUri,
    gcpBucket,
    storageClass: 'STANDARD',
    extractedIocs,
    samplePreview: textSnippet.slice(0, 500) || `[Binary / Byte stream file: ${formatBytes(fileSizeBytes)}]`,
    threatSignaturesMatched,
    safetyPercentage,
    safetyVerdict,
    safetyVerdictLabel,
    isSafe: safetyPercentage >= 80,
    safetyDeductions,
  };
}
