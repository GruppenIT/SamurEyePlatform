// OWASP API Top 10 2023 — pt-BR labels and OWASP reference URLs.
// Kept outside the pgEnum so UI translations can evolve without database migration.
// Keys MUST match the values of owasp_api_category pgEnum in shared/schema.ts.

export const OWASP_API_CATEGORY_LABELS = {
  api1_bola_2023: {
    codigo: "API1:2023",
    titulo: "Quebra de Autorização em Nível de Objeto",
    tituloIngles: "Broken Object Level Authorization",
    referenciaOwasp: "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
  },
  api2_broken_auth_2023: {
    codigo: "API2:2023",
    titulo: "Autenticação Quebrada",
    tituloIngles: "Broken Authentication",
    referenciaOwasp: "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
  },
  api3_bopla_2023: {
    codigo: "API3:2023",
    titulo: "Quebra de Autorização em Nível de Propriedade do Objeto",
    tituloIngles: "Broken Object Property Level Authorization",
    referenciaOwasp: "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
  },
  api4_rate_limit_2023: {
    codigo: "API4:2023",
    titulo: "Consumo Irrestrito de Recursos",
    tituloIngles: "Unrestricted Resource Consumption",
    referenciaOwasp: "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
  },
  api5_bfla_2023: {
    codigo: "API5:2023",
    titulo: "Quebra de Autorização em Nível de Função",
    tituloIngles: "Broken Function Level Authorization",
    referenciaOwasp: "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
  },
  api6_business_flow_2023: {
    codigo: "API6:2023",
    titulo: "Acesso Irrestrito a Fluxos de Negócio Sensíveis",
    tituloIngles: "Unrestricted Access to Sensitive Business Flows",
    referenciaOwasp: "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
  },
  api7_ssrf_2023: {
    codigo: "API7:2023",
    titulo: "Server Side Request Forgery (SSRF)",
    tituloIngles: "Server Side Request Forgery",
    referenciaOwasp: "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
  },
  api8_misconfiguration_2023: {
    codigo: "API8:2023",
    titulo: "Configuração Incorreta de Segurança",
    tituloIngles: "Security Misconfiguration",
    referenciaOwasp: "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
  },
  api9_inventory_2023: {
    codigo: "API9:2023",
    titulo: "Gestão de Inventário Inadequada",
    tituloIngles: "Improper Inventory Management",
    referenciaOwasp: "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
  },
  api10_unsafe_consumption_2023: {
    codigo: "API10:2023",
    titulo: "Consumo Inseguro de APIs",
    tituloIngles: "Unsafe Consumption of APIs",
    referenciaOwasp: "https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/",
  },
} as const;

export type OwaspApiCategory = keyof typeof OWASP_API_CATEGORY_LABELS;

// Allowed values for api_endpoints.discoverySources text[] column.
// Kept as TS constant (not pgEnum) so adding new sources (e.g. 'arjun') requires no migration.
export const DISCOVERY_SOURCES = ['spec', 'crawler', 'kiterunner', 'manual'] as const;
export type DiscoverySource = typeof DISCOVERY_SOURCES[number];
