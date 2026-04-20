/**
 * Phase 12 Wave 0 — Nyquist stub for Nuclei JSONL mapper.
 * Implementation comes in Wave 1 (12-02-PLAN — scanners/api/nucleiApi.ts).
 * Requirement: TEST-01
 */
import { describe, it } from 'vitest';

describe('nucleiApi: JSONL → ApiFindingEvidence mapper', () => {
  it.todo('parses NucleiFindingSchema.safeParse per line (rejects malformed lines)');
  it.todo('maps kebab-case (matched-at, template-id, extracted-results) to camelCase');
  it.todo('truncates request.body and response.body to 8192 chars (bodySnippet)');
  it.todo('maps Nuclei severity info→low, low→low, medium→medium, high→high, critical→critical');
  it.todo('sets owaspCategory api8_misconfiguration_2023 for tags misconfig/exposure/cors');
  it.todo('sets owaspCategory api9_inventory_2023 for tag graphql');
  it.todo('extracts evidence.extractedValues = { matcherName, extractedResults, templateId }');
  it.todo('copies nuclei.info.description into evidence.context');
});
