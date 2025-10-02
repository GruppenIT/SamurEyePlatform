# 📘 Guia de Atualização do SamurEye

## 🎯 Visão Geral

O script `update-samureye.sh` permite atualizar sua instalação on-premise do SamurEye **sem resetar o banco de dados**, preservando todos os seus dados (usuários, ameaças, políticas, credenciais, etc.).

## 🚀 Uso Básico

### Atualização Padrão (Recomendado)

```bash
cd /opt/samureye
sudo ./update-samureye.sh
```

O script irá:
1. ✅ Verificar se há atualizações disponíveis no GitHub
2. ✅ Criar backup completo do banco de dados e código
3. ✅ Parar o serviço temporariamente
4. ✅ Baixar atualizações do repositório
5. ✅ Instalar dependências atualizadas
6. ✅ Compilar a aplicação
7. ✅ Executar migrações do banco (sem perda de dados)
8. ✅ Reiniciar o serviço
9. ✅ Verificar integridade da atualização

## ⚙️ Opções Avançadas

### Atualização Sem Backup (Não Recomendado)

```bash
sudo SKIP_BACKUP=true ./update-samureye.sh
```

> ⚠️ **Atenção:** Use apenas se você já possui backups externos recentes.

### Atualização de um Branch Específico

```bash
sudo BRANCH=develop ./update-samureye.sh
```

### Personalizar Diretório de Instalação

```bash
sudo INSTALL_DIR=/custom/path ./update-samureye.sh
```

## 🛡️ Segurança e Backups

### Localização dos Backups

Todos os backups são salvos automaticamente em:

```
/opt/samureye/backups/
├── pre_update_db_YYYYMMDD_HHMMSS.sql    # Backup do banco de dados
├── pre_update_code_YYYYMMDD_HHMMSS.tar.gz  # Backup do código fonte
```

### Rollback Manual (Se Necessário)

Se algo der errado e o rollback automático falhar:

```bash
# 1. Restaurar banco de dados
cd /opt/samureye/backups
PGPASSWORD="sua_senha" psql -h localhost -U samureye -d samureye_db < pre_update_db_YYYYMMDD_HHMMSS.sql

# 2. Restaurar código
cd /opt/samureye
git reset --hard COMMIT_ANTERIOR
npm install
npm run build

# 3. Reiniciar serviço
sudo systemctl restart samureye-api
```

## 📊 O Que É Atualizado

### ✅ O QUE É ATUALIZADO:
- ✅ Código fonte da aplicação
- ✅ Dependências Node.js (npm packages)
- ✅ Schema do banco de dados (estrutura de tabelas)
- ✅ Configurações de build e compilação

### ❌ O QUE É PRESERVADO:
- ❌ **Banco de dados** (todos os dados permanecem intactos)
- ❌ Arquivo `.env` (configurações e credenciais)
- ❌ Logs existentes
- ❌ Backups anteriores
- ❌ Usuários, ameaças, políticas de notificação
- ❌ Credenciais criptografadas

## 🔍 Verificando a Atualização

### Após a atualização, verifique:

```bash
# Status do serviço
sudo systemctl status samureye-api

# Logs em tempo real
sudo journalctl -u samureye-api -f

# Versão instalada
cd /opt/samureye
git log -1 --oneline

# Testar API
curl http://localhost:5000/api/health
```

## 🆘 Solução de Problemas

### Problema: Serviço não inicia após atualização

```bash
# Verificar logs
sudo journalctl -u samureye-api -n 100 --no-pager

# Verificar arquivo de configuração
cat /opt/samureye/.env

# Testar conexão com banco
PGPASSWORD="sua_senha" psql -h localhost -U samureye -d samureye_db -c "SELECT 1;"
```

### Problema: Migrações do banco falham

Se `npm run db:push` falhar com avisos:

```bash
cd /opt/samureye
npm run db:push -- --force
```

> ⚠️ Leia os avisos cuidadosamente antes de usar `--force`

### Problema: Dependências não instalam

```bash
cd /opt/samureye
rm -rf node_modules package-lock.json
npm install --production=false
npm run build
sudo systemctl restart samureye-api
```

## 📅 Boas Práticas

1. **Backup Regular**: Execute backups manuais antes de grandes atualizações
   ```bash
   pg_dump -U samureye -d samureye_db > backup_manual_$(date +%Y%m%d).sql
   ```

2. **Horário de Manutenção**: Execute atualizações fora do horário comercial

3. **Teste Primeiro**: Se possível, teste em ambiente de desenvolvimento

4. **Monitore Após Atualização**: Acompanhe logs por pelo menos 1 hora após atualizar

5. **Mantenha Backups**: Não delete backups antigos por pelo menos 30 dias

## 📞 Suporte

Para problemas ou dúvidas:

- **Site**: https://www.samureye.com.br
- **Email**: suporte@gruppenitsecurity.com.br
- **GitHub**: https://github.com/GruppenIT/SamurEyePlatform

---

**Desenvolvido e Suportado por Gruppen IT Security** 🛡️
