// Phase 10 — CRED-03: helper de matching glob→regex para URL patterns.
// Função pura, sem I/O, sem dependências externas. Consumida por resolveApiCredential
// (Plan 04) e potencialmente pelo runtime do Phase 11.
//
// Algoritmo (CONTEXT.md decisões):
//   - Pattern `*` isolado = wildcard global (`.*`) — casa qualquer URL.
//   - `*` dentro de pattern maior = `[^/]*` (não cruza barra, uniforme em host e path).
//   - Demais caracteres regex são escapados (literais).

const REGEX_SPECIAL = /[.+^${}()|[\]\\]/g;

export function matchUrlPattern(pattern: string, url: string): boolean {
  if (!pattern || !url) return false;
  // Pattern `*` sozinho = wildcard global (caso especial explícito no CONTEXT.md).
  if (pattern === '*') return true;
  const escaped = pattern
    .replace(REGEX_SPECIAL, '\\$&') // escapa caracteres regex especiais (exceto *)
    .replace(/\*/g, '[^/]*'); // wildcards não cruzam barra
  const regex = new RegExp(`^${escaped}$`);
  return regex.test(url);
}

// Whitelist conservadora — rejeita patterns inválidos no POST.
// Runtime (Phase 11) confia que o pattern armazenado é válido.
const VALID_PATTERN = /^[a-zA-Z0-9:/.*?=&_\-{}~!$'()+,;%@#]+$/;

export function isValidUrlPattern(pattern: string): boolean {
  if (!pattern || pattern.length === 0) return false;
  if (pattern.includes('**')) return false; // ambíguo
  return VALID_PATTERN.test(pattern);
}
