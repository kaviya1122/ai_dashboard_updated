/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  calculateShannonEntropy,
  detectFileCategory,
  extractIocsFromContent,
  analyzeAnySecurityFile,
  formatBytes,
} from './fileAnalyzer';

test('detectFileCategory identifies all major security formats', () => {
  assert.equal(detectFileCategory('egress.csv', 'text/csv'), 'csv');
  assert.equal(detectFileCategory('eve.json', 'application/json'), 'json');
  assert.equal(detectFileCategory('auth.log', 'text/plain'), 'log');
  assert.equal(detectFileCategory('capture.pcap', 'application/vnd.tcpdump.pcap'), 'pcap');
  assert.equal(detectFileCategory('malware.exe', 'application/x-msdownload'), 'binary');
  assert.equal(detectFileCategory('dump.tar.gz', 'application/gzip'), 'archive');
  assert.equal(detectFileCategory('screenshot.png', 'image/png'), 'image');
  assert.equal(detectFileCategory('firmware.hex', 'application/octet-stream'), 'generic');
});

test('calculateShannonEntropy accurately distinguishes low vs high entropy', () => {
  // All zeroes -> 0 entropy
  const zeroes = new Uint8Array(1000).fill(0);
  assert.equal(calculateShannonEntropy(zeroes), 0);

  // High entropy pseudorandom bytes -> high entropy (>7)
  const random = new Uint8Array(256);
  for (let i = 0; i < 256; i++) random[i] = i;
  const entropy = calculateShannonEntropy(random);
  assert.ok(entropy >= 7.9, `Expected ~8, got ${entropy}`);
});

test('extractIocsFromContent pulls multiple indicator types', () => {
  const content = `Event from 10.240.10.42 contacting evil-c2.xyz regarding CVE-2021-44228. Contact: ops@threat.net`;
  const iocs = extractIocsFromContent(content);
  assert.ok(iocs.ips.includes('10.240.10.42'));
  assert.ok(iocs.domains.includes('evil-c2.xyz'));
  assert.ok(iocs.cves.includes('CVE-2021-44228'));
  assert.ok(iocs.emails.includes('ops@threat.net'));
});

test('analyzeAnySecurityFile accepts up to 100MB and reports local-only handling', () => {
  const file = analyzeAnySecurityFile({
    fileName: 'large_network_dump.pcap',
    fileSizeBytes: 85 * 1024 * 1024, // 85 MB
    mimeType: 'application/vnd.tcpdump.pcap',
    textSnippet: 'Packet capture from 10.240.1.1 to 198.51.100.89 port 443',
  });

  assert.equal(file.detectedFormat, 'pcap');
  assert.equal(file.fileSizeFormatted, '85 MB');
  assert.match(file.gcpStorageUri, /Not uploaded/);
  assert.equal(file.storageClass, 'STANDARD');
});

test('analyzeAnySecurityFile calculates 100% safety for clean configuration file', () => {
  const file = analyzeAnySecurityFile({
    fileName: 'cis_baseline_config.json',
    fileSizeBytes: 24000,
    mimeType: 'application/json',
    textSnippet: '{"compliance": "CIS-Level-1", "mfa_enforced": true, "tls_min": "1.3"}',
  });

  assert.equal(file.safetyPercentage, 100);
  assert.equal(file.safetyVerdict, 'safe');
  assert.equal(file.isSafe, true);
  assert.equal(file.safetyDeductions.length, 0);
  assert.ok(file.safetyVerdictLabel.includes('100% SAFE'));
});

test('analyzeAnySecurityFile penalizes CVE exploits, ransomware entropy, and malicious scripts', () => {
  const maliciousFile = analyzeAnySecurityFile({
    fileName: 'dropper_stage1.ps1',
    fileSizeBytes: 45000,
    mimeType: 'application/x-powershell',
    textSnippet: 'powershell.exe -enc aWV4 -w hidden\n$c2 = "evil-c2-beacon.xyz"\nExploit targeting CVE-2021-44228 payload heartbeat',
  });

  assert.ok(maliciousFile.safetyPercentage < 50, `Expected <50% safe, got ${maliciousFile.safetyPercentage}%`);
  assert.equal(maliciousFile.safetyVerdict, 'malicious');
  assert.equal(maliciousFile.isSafe, false);
  assert.ok(maliciousFile.safetyDeductions.length >= 2);
});

