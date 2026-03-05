# SamurEye – Plataforma de Validacao Adversarial de Exposicao

## Titulo

SamurEye – Plataforma de Validacao Adversarial de Exposicao

## Resumo

O SamurEye e uma plataforma de ciberseguranca para validacao adversarial continua de exposicao,
projetada para execucao em appliance Linux (virtual ou fisico). A solucao permite que organizacoes
identifiquem, monitorem e mitiguem riscos em sua superficie de ataque, seguranca de Active Directory,
e eficacia de solucoes EDR/AV.

A plataforma e composta por quatro modulos principais:
- **Interface Web (UI):** Frontend React + TypeScript com design responsivo, dashboards de postura
  de seguranca, gestao de ativos, credenciais, jornadas de verificacao e ameacas identificadas.
- **API Backend:** Servidor Node.js/Express + TypeScript com autenticacao local (Passport.js),
  RBAC (Global Administrator, Operator, Read-Only), sessoes seguras e auditoria completa.
- **Banco de Dados:** PostgreSQL com ORM Drizzle, schema versionado, criptografia AES-256-GCM
  para credenciais (modelo DEK/KEK).
- **Workers/Jobs:** Motor de execucao de jornadas com orquestracao de scanners externos (nmap,
  nuclei), analise LDAP de Active Directory, e testes EDR/AV via EICAR. Os resultados alimentam
  um Threat Engine que correlaciona e classifica ameacas automaticamente.

O SamurEye opera como solucao all-in-one, instalada e atualizada via scripts de deployment
(install.sh / update.sh), com suporte a TLS, hardening e observabilidade integrada.
