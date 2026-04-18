import { describe, it } from 'vitest';

describe('POST /api/v1/apis (HIER-03)', () => {
  it.todo('201 on happy path — returns created api row with id and createdBy');
  it.todo('409 when (parent_asset_id, base_url) duplicate — error.code 23505 mapped');
  it.todo('400 when parentAssetId does not exist');
  it.todo('400 when parent asset type !== web_application');
  it.todo('400 when baseUrl is not a parseable URL');
  it.todo('400 when apiType is not in [rest, graphql, soap]');
  it.todo('401 when unauthenticated');
  it.todo('403 when role is read_only (RBAC requireOperator)');
  it.todo('normalizes baseUrl via normalizeTarget() before insert');
  it.todo('writes audit log entry with actorId, action=create, objectType=api');
  it.todo('returns pt-BR error messages ("Ativo pai não encontrado", "URL base inválida", "API já cadastrada...")');
});
