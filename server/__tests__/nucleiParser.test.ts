import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { vulnScanner } from '../services/scanners/vulnScanner';

const fixturesDir = join(__dirname, 'fixtures/nuclei');

function loadFixture(name: string): string {
  return readFileSync(join(fixturesDir, name), 'utf-8');
}

describe('nucleiParser - parseNuclei', () => {
  it('returns empty array for empty string', () => {
    const findings = vulnScanner.parseNuclei('');
    expect(findings).toEqual([]);
  });

  it('parses xss-with-matcher fixture and populates PARS-06 fields', () => {
    const content = loadFixture('xss-with-matcher.jsonl');
    const findings = vulnScanner.parseNuclei(content);
    expect(findings).toMatchSnapshot();

    expect(findings).toHaveLength(1);
    const f = findings[0];
    expect(f.matcherName).toBe('generic-xss-reflection');
    expect(f.extractedResults).toEqual(['<script>alert(1)</script>', 'alert(1)']);
    expect(f.curlCommand).toContain('curl');
    expect(f.info.tags).toContain('xss');
    expect(f.info.tags).toContain('owasp');
  });

  it('parses cve-with-classification fixture and captures classification', () => {
    const content = loadFixture('cve-with-classification.jsonl');
    const findings = vulnScanner.parseNuclei(content);
    expect(findings).toMatchSnapshot();

    expect(findings).toHaveLength(1);
    const f = findings[0];
    expect(f.info.classification?.cveId).toContain('CVE-2021-44228');
    expect(f.info.classification?.cweId).toContain('CWE-502');
  });

  it('parses info-severity fixture with tags and references', () => {
    const content = loadFixture('info-severity-with-tags.jsonl');
    const findings = vulnScanner.parseNuclei(content);
    expect(findings).toMatchSnapshot();

    expect(findings).toHaveLength(1);
    const f = findings[0];
    expect(f.info.tags).toContain('tech');
    expect(f.info.tags).toContain('detect');
  });

  it('skips malformed lines and returns only valid findings', () => {
    const content = loadFixture('malformed-mixed-lines.jsonl');
    const findings = vulnScanner.parseNuclei(content);
    expect(findings).toMatchSnapshot();

    // Only 2 valid lines (line 2 is malformed JSON)
    expect(findings).toHaveLength(2);
  });
});
