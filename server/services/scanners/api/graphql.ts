// Phase 11 DISC-03 — GraphQL introspection + schema → endpoints mapping.
// Hard-coded introspection query avoids adding graphql-js dep (~700KB).
// Query literal derived from graphql-js getIntrospectionQuery() output as of spec.graphql.org/October2021.
import type { InsertApiEndpoint } from '@shared/schema';
import { createLogger } from '../../../lib/logger';

const log = createLogger('scanners:api:graphql');

// DISC-03 canonical path order.
export const GRAPHQL_PATHS: readonly string[] = ['/graphql', '/api/graphql', '/query'];

// Standard introspection query — DO NOT modify unless the GraphQL spec changes.
// https://spec.graphql.org/October2021/#sec-Introspection
export const INTROSPECTION_QUERY = `
  query IntrospectionQuery {
    __schema {
      queryType { name }
      mutationType { name }
      subscriptionType { name }
      types { ...FullType }
      directives { name description locations args { ...InputValue } }
    }
  }
  fragment FullType on __Type {
    kind name description
    fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason }
    inputFields { ...InputValue }
    interfaces { ...TypeRef }
    enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
    possibleTypes { ...TypeRef }
  }
  fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue }
  fragment TypeRef on __Type {
    kind name
    ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } }
  }
`;

export interface GraphQLProbeResult {
  schema: GraphQLSchema;
  endpointPath: string;
}

export interface GraphQLSchema {
  queryType?: { name: string } | null;
  mutationType?: { name: string } | null;
  subscriptionType?: { name: string } | null;
  types: GraphQLType[];
}

interface GraphQLType {
  kind: string;
  name: string;
  fields?: Array<{ name: string; args?: GraphQLInputValue[] }> | null;
}

interface GraphQLInputValue {
  name: string;
  type: { kind: string; name?: string; ofType?: unknown };
}

/**
 * DISC-03 — probe GRAPHQL_PATHS with a POST + standard introspection query.
 * Returns schema + discovered endpoint path on first 200 containing data.__schema.
 * Returns null if introspection is disabled on all 3 paths.
 */
export async function probeGraphQL(
  baseUrl: string,
  authHeader: string | undefined,
  signal: AbortSignal,
): Promise<GraphQLProbeResult | null> {
  for (const gqlPath of GRAPHQL_PATHS) {
    let url: string;
    try {
      url = new URL(gqlPath, baseUrl).toString();
    } catch {
      continue;
    }
    try {
      const res = await fetch(url, {
        method: 'POST',
        signal,
        headers: {
          'Content-Type': 'application/json',
          ...(authHeader ? { Authorization: authHeader } : {}),
        },
        body: JSON.stringify({ query: INTROSPECTION_QUERY }),
      });
      if (!res.ok) continue;
      const body = (await res.json()) as {
        data?: { __schema?: GraphQLSchema };
        errors?: unknown[];
      };
      if (body.data?.__schema) {
        log.info(
          {
            endpointPath: gqlPath,
            specPubliclyExposed: !authHeader,
            typeCount: body.data.__schema.types?.length ?? 0,
          },
          'graphql introspection succeeded',
        );
        return { schema: body.data.__schema, endpointPath: gqlPath };
      }
    } catch (err) {
      log.debug({ err: String(err), url }, 'graphql introspection failed; trying next path');
    }
  }
  return null;
}

/**
 * DISC-03 — map a GraphQL schema to InsertApiEndpoint rows.
 * One row per field on queryType, mutationType, subscriptionType.
 * method=POST, path=endpointPath (e.g. '/graphql'), discoverySources=['spec'].
 * requestSchema stores { operationName, operationType, variables } per CONTEXT.md.
 */
export function schemaToEndpoints(
  schema: GraphQLSchema,
  apiId: string,
  endpointPath: string,
): InsertApiEndpoint[] {
  const endpoints: InsertApiEndpoint[] = [];
  const typesByName = new Map<string, GraphQLType>();
  for (const t of schema.types ?? []) typesByName.set(t.name, t);

  const rootTypes: Array<[string, 'query' | 'mutation' | 'subscription']> = [];
  if (schema.queryType?.name) rootTypes.push([schema.queryType.name, 'query']);
  if (schema.mutationType?.name) rootTypes.push([schema.mutationType.name, 'mutation']);
  if (schema.subscriptionType?.name) rootTypes.push([schema.subscriptionType.name, 'subscription']);

  for (const [typeName, operationType] of rootTypes) {
    const typeDef = typesByName.get(typeName);
    if (!typeDef?.fields) continue;
    for (const field of typeDef.fields) {
      endpoints.push({
        apiId,
        method: 'POST',
        path: endpointPath,
        pathParams: [],
        queryParams: [],
        headerParams: [],
        requestSchema: {
          operationName: field.name,
          operationType,
          variables: (field.args ?? []).map((a) => ({
            name: a.name,
            type: describeTypeRef(a.type),
          })),
        },
        discoverySources: ['spec'],
      });
    }
  }
  return endpoints;
}

function describeTypeRef(
  t: { kind: string; name?: string; ofType?: unknown } | undefined | null,
): string {
  if (!t) return 'unknown';
  if (t.name) return t.name;
  if (t.kind === 'NON_NULL')
    return (
      describeTypeRef(t.ofType as { kind: string; name?: string; ofType?: unknown }) + '!'
    );
  if (t.kind === 'LIST')
    return '[' + describeTypeRef(t.ofType as { kind: string; name?: string; ofType?: unknown }) + ']';
  return t.kind;
}
