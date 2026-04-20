// Phase 11 DISC-01/DISC-02 — spec-first probe + native OpenAPI parsing.
// Uses fetch (no spawn). SSRF defense via same-origin $ref filter (Pitfall 1).
import SwaggerParser from '@apidevtools/swagger-parser';
import type { OpenAPI } from 'openapi-types';
import type { InsertApiEndpoint } from '@shared/schema';
import { createLogger } from '../../../lib/logger';
import { computeCanonicalHash } from './specHash';

const log = createLogger('scanners:api:openapi');

// DISC-01 canonical probe order. MUST iterate in this order.
export const KNOWN_SPEC_PATHS: readonly string[] = [
  '/openapi.json',
  '/swagger.json',
  '/v3/api-docs',
  '/v2/api-docs',
  '/api-docs',
  '/swagger-ui.html',
  '/docs/openapi',
];

export interface SpecFetchResult {
  spec: OpenAPI.Document;
  specUrl: string;
  specHash: string;
  specVersion: string;
}

/**
 * DISC-01 + DISC-02 — iterate KNOWN_SPEC_PATHS, short-circuit on first 200+JSON,
 * dereference with same-origin $ref guard, return parsed spec + hash + version.
 * Returns null when no path yields a parseable spec.
 */
export async function fetchAndParseSpec(
  baseUrl: string,
  authHeader: string | undefined,
  signal: AbortSignal,
): Promise<SpecFetchResult | null> {
  for (const specPath of KNOWN_SPEC_PATHS) {
    let url: string;
    try {
      url = new URL(specPath, baseUrl).toString();
    } catch {
      continue;
    }
    try {
      const res = await fetch(url, {
        method: 'GET',
        headers: authHeader ? { Authorization: authHeader } : {},
        signal,
        redirect: 'follow',
      });
      if (!res.ok) continue;
      const ct = (res.headers.get('content-type') ?? '').toLowerCase();
      // swagger-ui.html may serve HTML; skip non-JSON responses.
      if (!ct.includes('json')) continue;
      const rawSpec = await res.json();

      const specOrigin = new URL(url).origin;
      const spec = await SwaggerParser.dereference(rawSpec as OpenAPI.Document, {
        resolve: {
          http: {
            read: async (file: { url: string }) => {
              if (new URL(file.url).origin !== specOrigin) {
                log.warn({ specUrl: url, refUrl: file.url }, 'rejected cross-origin $ref (SSRF defense)');
                throw new Error('cross-origin $ref blocked');
              }
              const r = await fetch(file.url, { signal });
              return await r.text();
            },
          },
        },
      }) as OpenAPI.Document;

      const specHash = computeCanonicalHash(spec);
      const specVersion = extractSpecVersion(spec);
      log.info(
        { specUrl: url, specVersion, specHashPrefix: specHash.slice(0, 16), specPubliclyExposed: !authHeader },
        'spec fetched and parsed',
      );
      return { spec, specUrl: url, specHash, specVersion };
    } catch (err) {
      log.debug({ err: String(err), url }, 'spec fetch/parse failed; trying next path');
    }
  }
  return null;
}

function extractSpecVersion(spec: OpenAPI.Document): string {
  const s = spec as { openapi?: string; swagger?: string };
  if (typeof s.openapi === 'string') return s.openapi;
  if (typeof s.swagger === 'string') return s.swagger;
  return 'unknown';
}

/**
 * DISC-02 — map a dereferenced OpenAPI document to InsertApiEndpoint rows.
 * Iterates spec.paths[path][method] and extracts params (split by location),
 * requestSchema (from requestBody.content[json].schema), responseSchema (from
 * responses[2xx].content[json].schema). Sets discoverySources=['spec'].
 */
export function specToEndpoints(
  spec: unknown,
  apiId: string,
): InsertApiEndpoint[] {
  const endpoints: InsertApiEndpoint[] = [];
  const paths = (spec as { paths?: Record<string, unknown> }).paths ?? {};
  const HTTP_METHODS = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options'] as const;

  for (const [path, pathItemRaw] of Object.entries(paths)) {
    if (!pathItemRaw || typeof pathItemRaw !== 'object') continue;
    const pathItem = pathItemRaw as Record<string, unknown>;
    const pathLevelParams = Array.isArray(pathItem.parameters) ? pathItem.parameters : [];

    for (const method of HTTP_METHODS) {
      const opRaw = pathItem[method];
      if (!opRaw || typeof opRaw !== 'object') continue;
      const op = opRaw as {
        parameters?: unknown[];
        requestBody?: unknown;
        responses?: Record<string, unknown>;
      };
      const opParams = Array.isArray(op.parameters) ? op.parameters : [];
      const allParams = [...pathLevelParams, ...opParams] as Array<{
        name?: string;
        in?: 'path' | 'query' | 'header' | 'cookie';
        required?: boolean;
        schema?: { type?: string };
        type?: string;
        example?: unknown;
      }>;

      const pathParams: InsertApiEndpoint['pathParams'] = [];
      const queryParams: InsertApiEndpoint['queryParams'] = [];
      const headerParams: InsertApiEndpoint['headerParams'] = [];

      for (const p of allParams) {
        if (!p.name) continue;
        const entry = {
          name: p.name,
          type: p.schema?.type ?? p.type,
          required: p.required ?? false,
          example: p.example,
        };
        if (p.in === 'path') pathParams.push(entry);
        else if (p.in === 'query') queryParams.push(entry);
        else if (p.in === 'header') headerParams.push(entry);
      }

      const requestSchema = extractJsonSchema(op.requestBody);
      const responseSchema = extractFirstSuccessResponseSchema(op.responses);

      endpoints.push({
        apiId,
        method: method.toUpperCase(),
        path,
        pathParams,
        queryParams,
        headerParams,
        requestSchema,
        responseSchema,
        discoverySources: ['spec'],
      });
    }
  }
  return endpoints;
}

function extractJsonSchema(body: unknown): Record<string, unknown> | undefined {
  if (!body || typeof body !== 'object') return undefined;
  const content = (body as { content?: Record<string, { schema?: unknown }> }).content;
  if (!content) return undefined;
  const json = content['application/json']?.schema ?? content['application/*']?.schema;
  return json as Record<string, unknown> | undefined;
}

function extractFirstSuccessResponseSchema(
  responses: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  if (!responses) return undefined;
  for (const code of ['200', '201', '204', 'default']) {
    const r = responses[code] as { content?: Record<string, { schema?: unknown }> } | undefined;
    const s = r?.content?.['application/json']?.schema;
    if (s) return s as Record<string, unknown>;
  }
  return undefined;
}
