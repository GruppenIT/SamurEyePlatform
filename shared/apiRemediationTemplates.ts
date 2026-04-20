/**
 * Phase 12 — API_REMEDIATION_TEMPLATES (pt-BR)
 *
 * Constantes de remediação para findings API2/API8/API9 gerados pelos scanners
 * em `server/services/scanners/api/` e pelo orchestrator
 * `server/services/journeys/apiPassiveTests.ts`.
 *
 * Phase 14 (FIND-02) pode estender/sanitizar globalmente. Phase 12 aplica
 * defensive-by-default: mensagem fixa por vetor, sem dados dinâmicos
 * do ambiente do usuário.
 *
 * Convenção:
 *   - api8_misconfiguration_2023 — string única (Nuclei classifica via tag).
 *   - api9_inventory_2023 — objeto com 3 variantes (spec_exposed,
 *       graphql_introspection, hidden_endpoint).
 *   - api2_broken_auth_2023 — objeto com 4 variantes (alg_none, kid_injection,
 *       token_reuse, api_key_leakage).
 *
 * Uso:
 *   import { API_REMEDIATION_TEMPLATES } from '@shared/apiRemediationTemplates';
 *   const r = API_REMEDIATION_TEMPLATES.api2_broken_auth_2023.alg_none;
 */
export const API_REMEDIATION_TEMPLATES = {
  api8_misconfiguration_2023:
    "Revise as configurações de segurança do servidor e da aplicação. " +
    "Desabilite endpoints administrativos expostos publicamente (ex: /server-status, " +
    "/.git/config, /actuator). Aplique cabeçalhos de segurança (X-Frame-Options, " +
    "Content-Security-Policy, X-Content-Type-Options). Remova mensagens de erro " +
    "detalhadas em respostas de produção. Valide configurações CORS restringindo " +
    "Access-Control-Allow-Origin a origens explícitas, nunca reflete arbitrariamente " +
    "o header Origin quando Access-Control-Allow-Credentials é true.",

  api9_inventory_2023: {
    spec_exposed:
      "Restrinja o acesso à especificação OpenAPI/Swagger: exija autenticação, " +
      "limite por IP/VPN, ou remova completamente de produção. Especificações " +
      "publicamente acessíveis revelam a superfície de ataque completa da API " +
      "(endpoints, parâmetros, schemas de resposta). Mantenha a spec apenas em " +
      "ambientes de desenvolvimento e documentação interna.",

    graphql_introspection:
      "Desabilite GraphQL introspection em produção. Configure o servidor GraphQL " +
      "para rejeitar __schema, __type e queries meta em ambientes não-development. " +
      "Exemplos: Apollo Server `introspection: false`, GraphQL-Ruby " +
      "`disable_introspection_entry_points` em produção, Hasura via HASURA_GRAPHQL_ENABLE_CONSOLE=false.",

    hidden_endpoint:
      "Endpoints descobertos apenas por brute-force representam superfície de ataque " +
      "não documentada (API9 Improper Inventory). Remova endpoints legados não " +
      "utilizados, ou documente e autentique formalmente. Inclua todos os endpoints " +
      "ativos na especificação OpenAPI/GraphQL oficial e no inventário de segurança.",
  },

  api2_broken_auth_2023: {
    alg_none:
      "Rejeite explicitamente tokens JWT com alg=none. Valide o header " +
      "\"alg\" contra uma allowlist (ex: RS256, ES256, HS256) ANTES de qualquer " +
      "outra verificação. Bibliotecas vulneráveis aceitam alg=none por padrão " +
      "(RFC 7519 permite, mas nenhum produção real deve aceitar). Referência: " +
      "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",

    kid_injection:
      "Valide o campo \"kid\" (Key ID) do header JWT contra uma allowlist " +
      "estrita de identificadores conhecidos. NUNCA use o valor de \"kid\" " +
      "diretamente como caminho de arquivo, query SQL, ou URL de fetch — isso " +
      "permite path traversal (../../etc/passwd), SQL injection, e SSRF via " +
      "JWKS remoto malicioso. Trate \"kid\" como um identificador opaco que " +
      "resolve via lookup em estrutura em memória controlada.",

    token_reuse:
      "Implemente validação rigorosa do claim \"exp\" e mantenha uma blocklist " +
      "de tokens revogados (ex: logout). Tokens expirados (exp < now) devem ser " +
      "REJEITADOS independente de outras validações. Considere rotação de tokens " +
      "(refresh token pattern), TTL curto no access token (≤ 15min), e invalidação " +
      "de sessão server-side. Referência: OWASP Session Management Cheat Sheet.",

    api_key_leakage:
      "NUNCA inclua valores de API keys, tokens, ou secrets em response bodies, " +
      "logs de debug, ou mensagens de erro. Remova campos de depuração em builds " +
      "de produção. Aplique sanitização na camada de serialização (ex: remover " +
      "campos sensitivos antes de JSON.stringify). Considere rotação imediata da " +
      "chave vazada e auditoria de acessos desde a última data de uso.",
  },
} as const;

export type ApiRemediationTemplate = typeof API_REMEDIATION_TEMPLATES;
