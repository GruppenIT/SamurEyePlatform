-- Migração para ambiente on-premise: Correção de duplicatas e índice único
-- Execute este script no seu banco PostgreSQL para ativar a prevenção completa de duplicatas

BEGIN;

-- ETAPA 1: Consolidar duplicatas existentes (se houver)
-- Identifica e remove duplicatas, mantendo a ameaça mais antiga de cada correlationKey
WITH duplicates AS (
  SELECT 
    correlation_key,
    id,
    created_at,
    ROW_NUMBER() OVER (PARTITION BY correlation_key ORDER BY created_at ASC) as rn
  FROM threats 
  WHERE correlation_key IS NOT NULL
),
duplicates_to_remove AS (
  SELECT id
  FROM duplicates 
  WHERE rn > 1  -- Manter apenas a primeira (mais antiga)
)
DELETE FROM threat_status_history 
WHERE threat_id IN (SELECT id FROM duplicates_to_remove);

-- Remove as ameaças duplicadas (mantém apenas a mais antiga de cada correlationKey)
WITH duplicates AS (
  SELECT 
    correlation_key,
    id,
    created_at,
    ROW_NUMBER() OVER (PARTITION BY correlation_key ORDER BY created_at ASC) as rn
  FROM threats 
  WHERE correlation_key IS NOT NULL
)
DELETE FROM threats 
WHERE id IN (
  SELECT id 
  FROM duplicates 
  WHERE rn > 1
);

-- ETAPA 2: Criar índice único para prevenir futuras duplicatas
-- Este índice permite duplicatas apenas para ameaças fechadas como 'duplicate'
CREATE UNIQUE INDEX IF NOT EXISTS "UQ_threats_correlation_key" 
ON threats (correlation_key) 
WHERE (
  correlation_key IS NOT NULL 
  AND (status != 'closed' OR closure_reason != 'duplicate')
);

-- ETAPA 3: Verificar resultado
-- Esta query deve retornar zero linhas se a migração foi bem-sucedida
DO $$
DECLARE
  duplicate_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO duplicate_count
  FROM (
    SELECT correlation_key, COUNT(*)
    FROM threats 
    WHERE correlation_key IS NOT NULL
    GROUP BY correlation_key
    HAVING COUNT(*) > 1
  ) duplicates;
  
  IF duplicate_count > 0 THEN
    RAISE WARNING 'ATENÇÃO: Ainda existem % grupos de ameaças duplicadas após a migração!', duplicate_count;
  ELSE
    RAISE NOTICE 'SUCESSO: Nenhuma ameaça duplicada encontrada. Migração concluída com êxito!';
  END IF;
END $$;

COMMIT;

-- VERIFICAÇÃO FINAL (execute separadamente para conferir)
-- SELECT correlation_key, COUNT(*) as total, STRING_AGG(id, ', ') as ids 
-- FROM threats 
-- WHERE correlation_key IS NOT NULL
-- GROUP BY correlation_key
-- HAVING COUNT(*) > 1;
-- ↑ Esta query deve retornar zero linhas