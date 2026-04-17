import { describe, it, expect } from 'vitest';
import { sanitizeActionPlanHtml } from '../htmlSanitizer';

describe('sanitizeActionPlanHtml', () => {
  it('keeps allowed tags', () => {
    expect(sanitizeActionPlanHtml('<p><strong>hi</strong></p>')).toBe('<p><strong>hi</strong></p>');
  });
  it('strips scripts', () => {
    expect(sanitizeActionPlanHtml('<p>x</p><script>alert(1)</script>')).toBe('<p>x</p>');
  });
  it('strips event handlers', () => {
    const result = sanitizeActionPlanHtml('<a href="#" onclick="x()">y</a>');
    expect(result).not.toContain('onclick');
    expect(result).toContain('href="#"');
    expect(result).toContain('rel="noopener noreferrer"');
    expect(result).toContain('target="_blank"');
    expect(result).toContain('>y</a>');
  });
  it('rejects external images', () => {
    expect(sanitizeActionPlanHtml('<img src="https://evil/x.png">')).toBe('');
  });
  it('keeps internal images', () => {
    const url = '/api/v1/action-plans/images/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.png';
    expect(sanitizeActionPlanHtml(`<img src="${url}" alt="x">`)).toContain(url);
  });
});
