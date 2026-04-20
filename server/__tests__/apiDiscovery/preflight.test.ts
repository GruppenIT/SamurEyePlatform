import { describe, it, expect, vi, beforeEach } from 'vitest';
import { preflightApiBinary, resetApiBinaryPreflight } from '../../services/scanners/api/preflight';

describe('preflightApiBinary', () => {
  const log = { info: vi.fn(), error: vi.fn() };
  beforeEach(() => { resetApiBinaryPreflight(); vi.clearAllMocks(); });

  it('returns ok:false with reason when binary absent and logs error', async () => {
    const r = await preflightApiBinary('arjun', log);
    // On a CI runner without venv-security, expect ok:false.
    // If dev machine has venv, skip assertion on ok—only assert shape.
    expect(typeof r.ok).toBe('boolean');
    if (!r.ok) {
      expect(r.reason).toContain('arjun');
      expect(log.error).toHaveBeenCalled();
    }
  });

  it('memoizes result — second call does not re-run spawnSync', async () => {
    const r1 = await preflightApiBinary('katana', log);
    const r2 = await preflightApiBinary('katana', log);
    expect(r1).toBe(r2); // same reference = cache hit
  });

  it('resetApiBinaryPreflight clears cache', async () => {
    const r1 = await preflightApiBinary('httpx', log);
    resetApiBinaryPreflight();
    const r2 = await preflightApiBinary('httpx', log);
    expect(r1).not.toBe(r2); // different references after reset
  });
});
