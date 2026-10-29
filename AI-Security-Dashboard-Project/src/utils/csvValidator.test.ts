/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { parseAndValidateCsv } from './csvValidator';

test('parseAndValidateCsv parses clean CSV and extracts IOCs', () => {
  const sample = `timestamp,indicator,type,severity
2026-10-28T10:00:00Z,192.168.1.105,ip,critical
2026-10-28T10:05:00Z,malicious-domain.xyz,domain,high
2026-10-28T10:10:00Z,CVE-2021-44228,cve,critical`;

  const result = parseAndValidateCsv(sample, 'test.csv');
  assert.equal(result.totalRows, 3);
  assert.equal(result.validRows, 3);
  assert.equal(result.invalidRows, 0);
  assert.ok(result.extractedIocsSummary.ips.includes('192.168.1.105'));
  assert.ok(result.extractedIocsSummary.domains.includes('malicious-domain.xyz'));
  assert.ok(result.extractedIocsSummary.cves.includes('CVE-2021-44228'));
});

test('parseAndValidateCsv reports row mismatch errors', () => {
  const malformed = `timestamp,indicator,type
2026-10-28T10:00:00Z,192.168.1.105
2026-10-28T10:05:00Z,malicious-domain.xyz,domain`;

  const result = parseAndValidateCsv(malformed, 'malformed.csv');
  assert.equal(result.totalRows, 2);
  assert.equal(result.invalidRows, 1);
  assert.equal(result.validRows, 1);
  assert.ok(result.rows[0].errors[0].includes('Column count mismatch'));
});
