/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { checkNetworkScope, inspectAuthorizedPorts } from './networkScope';

test('checkNetworkScope strictly blocks unauthorized public IP targets', () => {
  const result = checkNetworkScope('8.8.8.8', true);
  assert.equal(result.isValidIpOrCidr, true);
  assert.equal(result.scopeType, 'unauthorized_public');
  assert.equal(result.isAuthorized, false);
  assert.ok(result.message.includes('Scope violation'));
});

test('checkNetworkScope allows RFC 1918 private subnets with consent', () => {
  const resConsent = checkNetworkScope('10.240.12.1', true);
  assert.equal(resConsent.isAuthorized, true);
  assert.equal(resConsent.scopeType, 'private_rfc1918');

  const resNoConsent = checkNetworkScope('10.240.12.1', false);
  assert.equal(resNoConsent.isAuthorized, false);
  assert.ok(resNoConsent.message.includes('Authorization required'));
});

test('checkNetworkScope handles localhost loopback', () => {
  const res = checkNetworkScope('127.0.0.1', true);
  assert.equal(res.isAuthorized, true);
  assert.equal(res.scopeType, 'loopback');
});

test('inspectAuthorizedPorts scores known critical ports (SMB 445, Telnet 23)', () => {
  const res = inspectAuthorizedPorts([445, 23]);
  assert.ok(res.totalRisk >= 70);
  assert.ok(res.findings.some((f) => f.port === 445 && f.service.includes('SMB')));
});
