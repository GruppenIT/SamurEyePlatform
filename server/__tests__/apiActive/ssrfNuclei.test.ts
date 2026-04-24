/**
 * Phase 13 Wave 0 — Nyquist stub for SSRF scanner with Nuclei + interactsh (TEST-07 / API7).
 * Implementation comes in Wave 1 (13-02-PLAN — scanners/api/ssrfNuclei.ts).
 * Requirement: TEST-07
 */
import { describe, it } from 'vitest';

describe('scanners/api/ssrfNuclei: identifyUrlParams (3 heuristics OR)', () => {
  it.todo('matches param.name via URL_LIKE_NAME_REGEX: url, redirect, redirect_uri, callback, callback_url, webhook, webhook_url, target, dest, destination, endpoint, uri, link, image_url, avatar_url, src, href, next, continue, returnTo, return_to, return (case-insensitive)');
  it.todo('matches param.type === "url" OR param.format === "uri" OR param.format === "url"');
  it.todo('matches param.example parseable by new URL() (without throwing)');
  it.todo('rejects params that match none of the 3 heuristics (e.g., name=userId, type=string, no example)');
});

describe('scanners/api/ssrfNuclei: buildSsrfNucleiArgs', () => {
  it.todo('includes -tags ssrf (ONLY ssrf tag, not misconfig/exposure)');
  it.todo('does NOT include -ni flag (interactsh MUST be enabled for SSRF OOB detection)');
  it.todo('includes -interactions-poll-duration 5s, -interactions-wait 10s, -interactions-retries-count 3');
  it.todo('includes -interactsh-url <url> when opts.interactshUrl OR env INTERACTSH_URL is set');
  it.todo('omits -interactsh-url when neither opts nor env is set (Nuclei defaults to oast.me)');
  it.todo('includes -rl 10 default, -timeout 30 (longer for OOB callback), -retries 0, -silent, -jsonl');
  it.todo('includes -t /tmp/nuclei/nuclei-templates (preflight-managed dir)');
});

describe('scanners/api/ssrfNuclei: finding criterion', () => {
  it.todo('emits SsrfHit when Nuclei JSONL reports interaction=true OR extracted-results contains callback URL match');
  it.todo('severity maps from Nuclei info→low, low→low, medium→medium, high→high, critical→critical');
  it.todo('title is "SSRF confirmado via interação out-of-band em parâmetro {{paramName}}" (paramName substituted)');
  it.todo('evidence.extractedValues includes paramName, interactsh_interaction_type (dns|http), interactshUrl masked (prefix-3 + ***)');
  it.todo('stage runs authenticated via resolveApiCredential (SSRF endpoints typically post-login)');
});

describe('scanners/api/ssrfNuclei: skip early when no URL params', () => {
  it.todo('skips stage with reason "no URL-like params found" when identifyUrlParams returns empty list');
  it.todo('avoids preflightNuclei call when no targets');
});
