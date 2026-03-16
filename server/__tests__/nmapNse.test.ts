import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { networkScanner } from '../services/scanners/networkScanner';

const fixturesDir = join(__dirname, 'fixtures/nmap');

describe('networkScanner.parseNmapXml - NSE script capture (PARS-02)', () => {
  it('parses vuln-ms17-010.xml and captures nseScripts array', () => {
    const xml = readFileSync(join(fixturesDir, 'vuln-ms17-010.xml'), 'utf-8');
    const findings = networkScanner.parseNmapXml(xml, '192.168.1.1');

    expect(findings).toHaveLength(1);
    const finding = findings[0];

    expect(finding.nseScripts).toBeDefined();
    expect(Array.isArray(finding.nseScripts)).toBe(true);
    expect(finding.nseScripts!.length).toBeGreaterThanOrEqual(1);
  });

  it('captures smb-vuln-ms17-010 script id and VULNERABLE output', () => {
    const xml = readFileSync(join(fixturesDir, 'vuln-ms17-010.xml'), 'utf-8');
    const findings = networkScanner.parseNmapXml(xml, '192.168.1.1');

    const finding = findings[0];
    const ms17Script = finding.nseScripts!.find(s => s.id === 'smb-vuln-ms17-010');

    expect(ms17Script).toBeDefined();
    expect(ms17Script!.id).toBe('smb-vuln-ms17-010');
    expect(ms17Script!.output).toContain('VULNERABLE');
    expect(ms17Script!.cves).toBeDefined();
    expect(ms17Script!.cves).toContain('CVE-2017-0144');
  });

  it('snapshots the full nseScripts array', () => {
    const xml = readFileSync(join(fixturesDir, 'vuln-ms17-010.xml'), 'utf-8');
    const findings = networkScanner.parseNmapXml(xml, '192.168.1.1');
    const finding = findings[0];

    expect(finding.nseScripts).toMatchSnapshot();
  });
});
