/**
 * Phase 16 — UI-04 — Curl Reproduction Dialog
 *
 * Wave 0 Nyquist stubs. Promoted to real it() by Plan 02 during Wave 1.
 * Per 16-VALIDATION.md task map.
 *
 * Requirement: "Reproduzir" action opens a Dialog with a <pre> block showing
 * the output of buildCurlCommand(finding). Copy button writes to clipboard.
 * Token-safety: never renders real secrets or "***" mask artifacts.
 */
import { describe, it } from 'vitest';

describe('UI-04 — Curl Reproduction Dialog', () => {
  it.todo('Dialog opens when "Reproduzir" row action is clicked');
  it.todo('<pre> block renders output of buildCurlCommand(finding) as monospace text');
  it.todo('Copy button calls navigator.clipboard.writeText with the exact curl string');
  it.todo('toast notification fires after successful clipboard copy');
  it.todo('Dialog renders fallback message when buildCurlCommand returns null');
  it.todo('curl output NEVER contains string "***" or any real credential token value');
  it.todo('Dialog shows correct auth placeholder per finding authType (e.g. $BEARER_TOKEN for bearer_jwt)');
});
