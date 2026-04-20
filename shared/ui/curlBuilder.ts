export const AUTH_PLACEHOLDER: Record<string, string> = {
  api_key_header: '-H "X-API-Key: $API_KEY"',
  api_key_query: '', // appended to URL instead
  bearer_jwt: '-H "Authorization: Bearer $BEARER_TOKEN"',
  basic: '-H "Authorization: Basic $BASIC_AUTH"',
  oauth2_client_credentials: '-H "Authorization: Bearer $BEARER_TOKEN"',
  hmac: '-H "Authorization: HMAC $HMAC_SIGNATURE"',
  mtls: '--cert $MTLS_CERT --key $MTLS_KEY',
};

export interface FindingLike {
  evidence?: {
    url?: string;
    method?: string;
    authType?: string;
    requestSchema?: unknown;
    headers?: Record<string, string>;
  } | null;
}

export function buildCurlCommand(finding: FindingLike): string | null {
  const ev = finding.evidence;
  if (!ev?.url || !ev?.method) return null;
  // NEVER read ev.headers values into curl — they may contain redacted tokens.
  let url = ev.url;
  const authType = ev.authType ?? '';
  const authFlag = AUTH_PLACEHOLDER[authType] ?? '';
  if (authType === 'api_key_query') {
    const sep = url.includes('?') ? '&' : '?';
    url = `${url}${sep}api_key=$API_KEY`;
  }
  const contentTypeLine = ev.requestSchema ? '-H "Content-Type: application/json"' : '';
  const bodyLine = ev.requestSchema
    ? `  -d '${JSON.stringify(ev.requestSchema).slice(0, 500)}'`
    : '';
  const lines: string[] = [`curl -X ${ev.method.toUpperCase()} "${url}" \\`];
  if (authFlag) lines.push(`  ${authFlag} \\`);
  if (contentTypeLine) lines.push(`  ${contentTypeLine} \\`);
  if (bodyLine) lines.push(bodyLine);
  // Trim trailing backslash on the last line
  const last = lines[lines.length - 1];
  if (last.endsWith(' \\')) lines[lines.length - 1] = last.slice(0, -2);
  return lines.join('\n');
}
