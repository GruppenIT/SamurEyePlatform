/**
 * Phase 16 — UI-02 — API Endpoint Drilldown Sheet
 *
 * Wave 0 Nyquist stubs. Promoted to real it() by Plans 02-03 during Waves 2-4.
 * Per 16-VALIDATION.md task map.
 *
 * Requirement: Sheet slides open from the right showing endpoints grouped by path.
 * Each path-group is a Collapsible. METHOD_COLORS drives Badge color.
 * requiresAuth=true shows a lock icon or badge.
 * Param chips: path=orange, query=blue, header=purple.
 */
import { describe, it } from 'vitest';

describe('UI-02 — API Endpoint Drilldown Sheet', () => {
  it.todo('Sheet opens when selectedApiId prop is set (not null)');
  it.todo('endpoints grouped by path: one Collapsible rendered per distinct path');
  it.todo('method Badge color applies METHOD_COLORS (e.g. GET → green class)');
  it.todo('requiresAuth=true renders lock icon or "Auth" badge indicator');
  it.todo('path param chip renders with orange Tailwind class');
  it.todo('query param chip renders with blue Tailwind class');
  it.todo('header param chip renders with purple Tailwind class');
  it.todo('renders empty-state "Nenhum endpoint descoberto" when endpoints array is empty');
});
