/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { test, describe } from 'node:test';
import assert from 'node:assert';

interface MockUserAccount {
  email: string;
  name: string;
  passwordHash: string;
  role: string;
}

class UserRegistry {
  private users: Map<string, MockUserAccount> = new Map();

  register(email: string, password: string, name?: string, role?: string): { success: boolean; error?: string } {
    const normalized = email.trim().toLowerCase();
    if (!normalized.includes('@')) {
      return { success: false, error: 'Invalid email' };
    }
    if (password.length < 6) {
      return { success: false, error: 'Password too short' };
    }
    if (this.users.has(normalized)) {
      return { success: false, error: 'An account with this email address already exists. Please log in instead.' };
    }
    this.users.set(normalized, {
      email: normalized,
      name: name || normalized.split('@')[0],
      passwordHash: `hash_${password}`,
      role: role || 'Security Analyst',
    });
    return { success: true };
  }

  login(email: string, password?: string): { success: boolean; error?: string; user?: MockUserAccount } {
    const normalized = email.trim().toLowerCase();
    const existing = this.users.get(normalized);
    if (!existing) {
      return { success: false, error: 'No account found with this email. Please create an account.' };
    }
    if (password && existing.passwordHash !== `hash_${password}`) {
      return { success: false, error: 'Incorrect password.' };
    }
    return { success: true, user: existing };
  }
}

describe('User Authentication & Email Uniqueness', () => {
  test('creates new user account successfully', () => {
    const registry = new UserRegistry();
    const res = registry.register('kaviya2006t@gmail.com', 'securePass123', 'Kaviya T', 'Security Analyst');
    assert.strictEqual(res.success, true);
  });

  test('prevents duplicate account creation with the same email', () => {
    const registry = new UserRegistry();
    registry.register('kaviya2006t@gmail.com', 'securePass123', 'Kaviya T');

    // Attempting to register again with same email
    const duplicate = registry.register('kaviya2006t@gmail.com', 'anotherPass456', 'Different Name');
    assert.strictEqual(duplicate.success, false);
    assert.match(duplicate.error!, /already exists/i);
  });

  test('email uniqueness is case-insensitive', () => {
    const registry = new UserRegistry();
    registry.register('User.One@Example.com', 'secret123');

    const duplicate = registry.register('user.one@example.com', 'secret123');
    assert.strictEqual(duplicate.success, false);
    assert.match(duplicate.error!, /already exists/i);
  });

  test('validates minimum password length', () => {
    const registry = new UserRegistry();
    const res = registry.register('newuser@example.com', '12345');
    assert.strictEqual(res.success, false);
    assert.match(res.error!, /short/i);
  });

  test('login succeeds with correct credentials and fails with wrong credentials', () => {
    const registry = new UserRegistry();
    registry.register('analyst@example.com', 'correctPassword123');

    const wrongLogin = registry.login('analyst@example.com', 'wrongPassword');
    assert.strictEqual(wrongLogin.success, false);
    assert.match(wrongLogin.error!, /incorrect password/i);

    const nonExistent = registry.login('unknown@example.com', 'pass123');
    assert.strictEqual(nonExistent.success, false);
    assert.match(nonExistent.error!, /no account found/i);

    const okLogin = registry.login('analyst@example.com', 'correctPassword123');
    assert.strictEqual(okLogin.success, true);
    assert.strictEqual(okLogin.user?.email, 'analyst@example.com');
  });
});
