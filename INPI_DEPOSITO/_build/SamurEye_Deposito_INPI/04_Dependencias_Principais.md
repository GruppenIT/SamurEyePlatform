# Dependencias Principais do SamurEye

## Frontend (React + TypeScript)

| Dependencia              | Finalidade                                      |
|--------------------------|------------------------------------------------|
| react 18.x               | Biblioteca de UI reativa                        |
| react-dom 18.x           | Renderizacao do React no navegador              |
| wouter 3.x               | Roteamento SPA leve                             |
| @tanstack/react-query 5.x| Gerenciamento de estado de servidor (cache/fetch)|
| react-hook-form 7.x      | Formularios com validacao                       |
| @hookform/resolvers       | Integra Zod com react-hook-form                 |
| zod 3.x                  | Validacao de schemas (compartilhado com backend)|
| recharts 2.x             | Graficos e dashboards                           |
| @radix-ui/*              | Componentes UI acessiveis (shadcn/ui)           |
| lucide-react             | Icones SVG                                      |
| framer-motion            | Animacoes de interface                          |
| tailwindcss 3.x          | Framework CSS utilitario                        |
| vite 5.x                 | Bundler e dev server                            |
| typescript 5.x           | Tipagem estatica                                |

## Backend (Node.js/Express + TypeScript)

| Dependencia              | Finalidade                                      |
|--------------------------|------------------------------------------------|
| express 4.x              | Framework HTTP/REST                             |
| passport 0.7.x           | Autenticacao modular                            |
| passport-local           | Estrategia de autenticacao local (email/senha)  |
| express-session          | Gestao de sessoes server-side                   |
| connect-pg-simple        | Armazenamento de sessoes em PostgreSQL          |
| bcryptjs 3.x             | Hashing de senhas                               |
| drizzle-orm 0.39.x       | ORM para PostgreSQL com tipagem forte           |
| drizzle-kit 0.30.x       | Ferramentas de migracao de schema               |
| drizzle-zod              | Geracao de schemas Zod a partir de tabelas      |
| pg 8.x                   | Driver PostgreSQL nativo                        |
| ws 8.x                   | WebSocket server para atualizacoes em tempo real|
| ldapts 8.x               | Cliente LDAP para analise de Active Directory   |
| ssh2 1.x                 | Cliente SSH para coleta remota                  |
| nodemailer 7.x           | Envio de emails (notificacoes/alertas)          |
| @azure/msal-node         | Autenticacao OAuth2 com Azure AD/Entra ID       |
| googleapis               | Integracao com APIs Google (OAuth2 email)        |
| openid-client             | Cliente OpenID Connect                          |
| nanoid 5.x               | Geracao de IDs unicos                           |
| esbuild                  | Bundler de producao para o backend              |
| tsx                      | Executor TypeScript para desenvolvimento        |

## Banco de Dados

| Tecnologia               | Finalidade                                      |
|--------------------------|------------------------------------------------|
| PostgreSQL 14+           | Banco relacional principal                      |
| Drizzle ORM              | Mapeamento objeto-relacional type-safe          |
| AES-256-GCM (crypto)     | Criptografia de credenciais (modelo DEK/KEK)    |

## Ferramentas Externas (orquestradas pelo backend)

| Ferramenta               | Finalidade                                      |
|--------------------------|------------------------------------------------|
| nmap                     | Scan de portas e descoberta de servicos         |
| nuclei                   | Scan de vulnerabilidades web                    |
| LDAP (via ldapts)        | Analise de Active Directory                     |
| SMB/WinRM                | Coleta de dados e testes EDR/AV (EICAR)         |
