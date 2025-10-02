# Configuração de OAuth2 para Notificações por Email

Este guia fornece instruções completas para configurar a autenticação OAuth2 com Google Workspace/Gmail e Microsoft 365 para o sistema de notificações por email do SamurEye.

## Índice
- [Por que usar OAuth2?](#por-que-usar-oauth2)
- [Configuração Google Workspace/Gmail](#configuração-google-workspacegmail)
- [Configuração Microsoft 365](#configuração-microsoft-365)
- [Configuração no SamurEye](#configuração-no-samureye)
- [Solução de Problemas](#solução-de-problemas)

---

## Por que usar OAuth2?

⚠️ **Importante**: A autenticação básica por senha (SMTP tradicional) está sendo **descontinuada** tanto pela Google quanto pela Microsoft em 2025. OAuth2 é o método recomendado e mais seguro para:

- **Segurança**: Tokens com escopo limitado em vez de senhas completas
- **Tokens de curta duração**: Access tokens expiram, minimizando riscos
- **Refresh automático**: Tokens são renovados automaticamente
- **Revogação fácil**: Acesso pode ser revogado sem alterar senhas

---

## Configuração Google Workspace/Gmail

### 1. Criar Projeto no Google Cloud Console

1. Acesse [Google Cloud Console](https://console.cloud.google.com/)
2. Clique no dropdown de projetos (canto superior) → **Novo Projeto**
3. Insira um **Nome do Projeto** (ex: "SamurEye Email")
4. Clique em **Criar**
5. Certifique-se de que seu novo projeto está selecionado

### 2. Habilitar a Gmail API

1. Vá para **APIs e Serviços > Biblioteca**
2. Busque por **"Gmail API"**
3. Clique nela e pressione **Ativar**

### 3. Configurar Tela de Consentimento OAuth

1. Vá para **APIs e Serviços > Tela de consentimento OAuth**
2. Escolha o **Tipo de usuário**:
   - **Interno**: Apenas para usuários da organização Google Workspace
   - **Externo**: Para qualquer usuário com conta Google (incluindo @gmail.com)
3. Clique em **Criar**
4. Preencha os campos obrigatórios:
   - **Nome do app**: Nome que os usuários verão (ex: "SamurEye Notifications")
   - **E-mail de suporte do usuário**: Seu email
   - **Informações de contato do desenvolvedor**: Seu email
5. Clique em **Salvar e Continuar**
6. **(Opcional)** Adicione escopos se solicitado, ou pule por enquanto
7. **(Para apps Externos)** Adicione usuários de teste se seu app estiver em modo "Teste"
8. **IMPORTANTE**: Altere o status de publicação para **"Em Produção"** (caso contrário, os refresh tokens expiram em 7 dias)
   - Vá para **Tela de consentimento OAuth** → **Publicar Aplicativo**
   - Nota: Para apps em produção com escopos sensíveis, a Google pode exigir verificação

### 4. Criar Credenciais OAuth 2.0

1. Vá para **APIs e Serviços > Credenciais**
2. Clique em **+ Criar Credenciais > ID do cliente OAuth**
3. Selecione **Tipo de aplicativo**:
   - **Aplicativo da Web**: Para aplicações web/servidor (recomendado)
   - **App para computador**: Para scripts locais/CLI
4. Insira um **Nome** (ex: "SamurEye OAuth Client")
5. **(Para aplicativos da Web)** Adicione **URIs de redirecionamento autorizados**:
   - Para produção: `https://seu-dominio.com/oauth2callback`
   - Para teste local: `http://localhost:8080/oauth2callback`
6. Clique em **Criar**

### 5. Obter Client ID e Client Secret

Após criar o cliente OAuth, um modal aparecerá com:
- **ID do cliente** (ex: `123456789-abc.apps.googleusercontent.com`)
- **Chave secreta do cliente** (ex: `GOCSPX-xyz...`)

**Copie e salve essas credenciais com segurança.**

### 6. Obter Refresh Token

Para obter o Refresh Token, você precisa executar o fluxo de autorização OAuth2:

#### Opção A: Usando OAuth 2.0 Playground (Método Rápido)

1. Acesse [OAuth 2.0 Playground](https://developers.google.com/oauthplayground/)
2. Clique no ícone de engrenagem (⚙️) no canto superior direito
3. Marque **"Use your own OAuth credentials"**
4. Insira seu **Client ID** e **Client Secret**
5. No campo à esquerda, procure por **"Gmail API v1"**
6. Selecione o escopo: `https://mail.google.com/` (para envio de emails)
7. Clique em **"Authorize APIs"**
8. Faça login com a conta Google que enviará os emails
9. Conceda as permissões solicitadas
10. Clique em **"Exchange authorization code for tokens"**
11. **Copie o Refresh Token** que aparecerá

#### Opção B: Usando Script Python

```python
from google_auth_oauthlib.flow import InstalledAppFlow

# Salve suas credenciais em credentials.json
SCOPES = ['https://mail.google.com/']

flow = InstalledAppFlow.from_client_secrets_file(
    'credentials.json',
    scopes=SCOPES,
    redirect_uri='http://localhost:8080'
)

# Isso abrirá o navegador para autorização
credentials = flow.run_local_server(port=8080, prompt='consent')

# Salve o refresh token
print(f"Refresh Token: {credentials.refresh_token}")
```

#### Opção C: Manualmente via URL

1. Crie esta URL (substitua os valores):
```
https://accounts.google.com/o/oauth2/v2/auth?
  client_id=SEU_CLIENT_ID
  &redirect_uri=http://localhost:8080
  &response_type=code
  &scope=https://mail.google.com/
  &access_type=offline
  &prompt=consent
```

2. Abra a URL no navegador
3. Faça login e autorize
4. Você será redirecionado para: `http://localhost:8080?code=CODIGO_DE_AUTORIZACAO`
5. Copie o `code` da URL
6. Faça uma requisição POST:

```bash
curl -X POST https://oauth2.googleapis.com/token \
  -d "code=CODIGO_DE_AUTORIZACAO" \
  -d "client_id=SEU_CLIENT_ID" \
  -d "client_secret=SEU_CLIENT_SECRET" \
  -d "redirect_uri=http://localhost:8080" \
  -d "grant_type=authorization_code"
```

7. A resposta conterá o `refresh_token`

### Credenciais Necessárias para o SamurEye (Gmail):

- **Client ID**: `123456789-abc.apps.googleusercontent.com`
- **Client Secret**: `GOCSPX-xyz...`
- **Refresh Token**: `1//abc...` (obtido no passo 6)

---

## Configuração Microsoft 365

### 1. Registrar Aplicação no Azure Portal

1. Acesse [Azure Portal](https://portal.azure.com) com credenciais de administrador
2. Vá para **Microsoft Entra ID** (anteriormente Azure Active Directory)
3. Selecione **Registros de aplicativo** → **Novo registro**
4. Preencha:
   - **Nome**: Nome do app (ex: "SamurEye Email OAuth")
   - **Tipos de conta com suporte**: Escolha conforme sua necessidade:
     - **Somente este diretório organizacional** (single tenant)
     - **Qualquer diretório organizacional** (multi-tenant)
   - **URI de Redirecionamento**: Selecione **Web** e adicione:
     - `https://login.microsoftonline.com/common/oauth2/nativeclient` (recomendado para obter refresh token)
     - OU `https://jwt.ms` (para teste rápido)
     - OU `http://localhost:8080` (para desenvolvimento local)
5. Clique em **Registrar**

**IMPORTANTE**: Se você não adicionou o redirect URI no passo 4, adicione agora:
- Vá para **Autenticação** (menu lateral)
- Em **URIs de redirecionamento**, clique em **Adicionar URI**
- Adicione: `https://login.microsoftonline.com/common/oauth2/nativeclient`
- Clique em **Salvar**

### 2. Obter Application (Client) ID e Tenant ID

Após o registro, na página **Visão Geral**:

- **ID do Aplicativo (cliente)**: Copie este GUID (este é seu `client_id`)
- **ID do Diretório (locatário)**: Copie este GUID (este é seu `tenant_id`)

### 3. Criar Client Secret

1. No seu registro de aplicativo, vá para **Certificados e segredos** (menu lateral)
2. Clique em **Novo segredo do cliente**
3. Preencha:
   - **Descrição**: Nome identificador (ex: "SMTP Secret")
   - **Expira**: Escolha a duração (recomendado: 24 meses)
4. Clique em **Adicionar**
5. **⚠️ CRÍTICO**: Copie o **Valor** do campo imediatamente antes de sair da página
   - Este é seu `client_secret`
   - Você NÃO poderá visualizá-lo novamente (apenas o ID do Segredo)
   - Guarde-o com segurança

### 4. Adicionar Permissões de API SMTP

1. Vá para **Permissões de API** → **Adicionar uma permissão**
2. Selecione **APIs que a minha organização usa**
3. Busque por **"Office 365 Exchange Online"**
4. Clique em **Permissões de aplicativo** (não Delegadas)
5. Selecione a permissão: **SMTP.Send** ou **SMTP.SendAsApp**
6. Clique em **Adicionar permissões**
7. Clique em **Conceder consentimento de administrador para [Nome do Locatário]** → **Sim**

### 5. Registrar Service Principal no Exchange Online

Este é um passo crítico frequentemente esquecido. Execute estes comandos PowerShell:

```powershell
# Instalar módulo Exchange Online Management
Install-Module -Name ExchangeOnlineManagement -Force

# Conectar ao Exchange Online
Connect-ExchangeOnline -UserPrincipalName admin@seudominio.com

# Registrar o service principal (use seu Client ID)
New-ServicePrincipal -AppId SEU_CLIENT_ID -ObjectId SEU_OBJECT_ID

# Conceder permissões de caixa de correio (para a caixa que enviará emails)
Add-MailboxPermission -Identity "remetente@seudominio.com" -User SEU_CLIENT_ID -AccessRights FullAccess

Add-RecipientPermission -Identity "remetente@seudominio.com" -Trustee SEU_CLIENT_ID -AccessRights SendAs -Confirm:$false
```

**Nota**: Obtenha seu **Object ID** em:
Azure Portal → **Aplicativos Empresariais** → Busque seu app → Copie **ID do Objeto**

### 6. Habilitar SMTP Autenticado

1. Acesse [Centro de Administração do Microsoft 365](https://admin.microsoft.com)
2. Vá para **Usuários** → **Usuários ativos**
3. Selecione o usuário da caixa de correio que enviará emails
4. Clique em **Email** → **Gerenciar aplicativos de email**
5. Certifique-se de que **SMTP Autenticado** está habilitado

### 7. Obter Refresh Token (Microsoft 365)

⚠️ **Importante**: Para SMTP OAuth2 com Microsoft, você usará **Client Credentials Flow**, que NÃO usa refresh tokens. Em vez disso, você obtém access tokens diretamente usando Client ID + Client Secret.

No entanto, se precisar do **Authorization Code Flow** (com refresh token para acesso delegado):

#### Passo A: Obter Código de Autorização

⚠️ **IMPORTANTE**: Use o redirect URI que você registrou no Azure Portal (passo 1).

Crie esta URL (substitua os valores):

```
https://login.microsoftonline.com/SEU_TENANT_ID/oauth2/v2.0/authorize?client_id=SEU_CLIENT_ID&response_type=code&redirect_uri=https://login.microsoftonline.com/common/oauth2/nativeclient&response_mode=query&scope=offline_access%20https://outlook.office365.com/.default&state=12345
```

**Versão formatada** (remova as quebras de linha ao usar):
```
https://login.microsoftonline.com/SEU_TENANT_ID/oauth2/v2.0/authorize?
  client_id=SEU_CLIENT_ID
  &response_type=code
  &redirect_uri=https://login.microsoftonline.com/common/oauth2/nativeclient
  &response_mode=query
  &scope=offline_access https://outlook.office365.com/.default
  &state=12345
```

**⚠️ ATENÇÃO**: 
- O scope correto é `https://outlook.office365.com/.default` (não `SMTP.Send`)
- Use o mesmo `redirect_uri` que você registrou no Azure Portal

1. Abra a URL no navegador (copie e cole em uma linha única)
2. Faça login com a conta Microsoft 365 que enviará emails
3. Conceda as permissões solicitadas
4. Você será redirecionado para uma página com o código na URL:
   - Se usou `nativeclient`: A página mostrará o código diretamente
   - Se usou `jwt.ms`: O código aparecerá decodificado
   - Se usou `localhost:8080`: Copie o código da URL
5. Copie o valor do parâmetro `code` da URL

#### Passo B: Trocar Código por Tokens

⚠️ **Use o MESMO redirect_uri** que você usou no Passo A.

```bash
curl -X POST https://login.microsoftonline.com/SEU_TENANT_ID/oauth2/v2.0/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=SEU_CLIENT_ID" \
  -d "client_secret=SEU_CLIENT_SECRET" \
  -d "code=CODIGO_DO_PASSO_A" \
  -d "redirect_uri=https://login.microsoftonline.com/common/oauth2/nativeclient" \
  -d "grant_type=authorization_code" \
  -d "scope=https://outlook.office365.com/.default"
```

**Nota**: Substitua `SEU_TENANT_ID`, `SEU_CLIENT_ID`, `SEU_CLIENT_SECRET` e `CODIGO_DO_PASSO_A` pelos seus valores reais.

A resposta conterá:
```json
{
  "access_token": "eyJ0eXAi...",
  "refresh_token": "0.AXoA...",
  "expires_in": 3599,
  "token_type": "Bearer",
  "scope": "https://outlook.office365.com/.default"
}
```

**Copie e salve o `refresh_token`** - você vai precisar dele para configurar o SamurEye.

### Credenciais Necessárias para o SamurEye (Microsoft 365):

- **Client ID**: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
- **Client Secret**: `abc123...`
- **Tenant ID**: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
- **Refresh Token**: `OAAABAAAAiL9Kn2Z...` (obtido no passo 7)

---

## Configuração no SamurEye

### 1. Acessar Configurações

1. Faça login como **Administrador Global**
2. Vá para **Configurações** (menu lateral)
3. Role até a seção **Configurações de E-mail SMTP**

### 2. Configurar para Gmail

1. Preencha os campos básicos:
   - **Servidor SMTP**: `smtp.gmail.com`
   - **Porta**: `587`
   - **Conexão Segura (TLS/SSL)**: Ativado ✅

2. Selecione **Tipo de Autenticação**: `OAuth2 - Google Workspace/Gmail`

3. Preencha as credenciais OAuth2:
   - **Client ID**: Cole o Client ID obtido do Google Cloud Console
   - **Client Secret**: Cole o Client Secret
   - **Refresh Token**: Cole o Refresh Token obtido

4. Preencha os dados do remetente:
   - **E-mail Remetente**: O email que enviará as notificações (ex: `notificacoes@suaempresa.com`)
   - **Nome do Remetente**: Nome que aparecerá (ex: `SamurEye Alertas`)

5. Clique em **Salvar Configurações de E-mail**

### 3. Configurar para Microsoft 365

1. Preencha os campos básicos:
   - **Servidor SMTP**: `smtp.office365.com`
   - **Porta**: `587`
   - **Conexão Segura (TLS/SSL)**: Ativado ✅

2. Selecione **Tipo de Autenticação**: `OAuth2 - Microsoft 365`

3. Preencha as credenciais OAuth2:
   - **Client ID**: Cole o Application (Client) ID do Azure
   - **Client Secret**: Cole o Client Secret criado
   - **Refresh Token**: Cole o Refresh Token obtido
   - **Tenant ID (Microsoft)**: Cole o Directory (Tenant) ID do Azure

4. Preencha os dados do remetente:
   - **E-mail Remetente**: O email que enviará as notificações (ex: `alertas@suaempresa.com`)
   - **Nome do Remetente**: Nome que aparecerá (ex: `SamurEye Security`)

5. Clique em **Salvar Configurações de E-mail**

### 4. Testar Configuração

1. Na seção **Teste de E-mail**, insira um email de destino
2. Clique em **Enviar E-mail de Teste**
3. Verifique se o email foi recebido corretamente

---

## Solução de Problemas

### Gmail

**Problema**: "Error: invalid_grant"
- **Solução**: O refresh token pode ter expirado (7 dias no modo teste). Publique o app no Google Cloud Console ou gere um novo refresh token.

**Problema**: "Access blocked: This app's request is invalid"
- **Solução**: Certifique-se de que o escopo `https://mail.google.com/` está configurado corretamente na tela de consentimento.

**Problema**: Refresh token não foi retornado
- **Solução**: Use `access_type=offline` e `prompt=consent` na URL de autorização. O refresh token só é retornado na primeira autorização.

**Problema**: "daily limit exceeded"
- **Solução**: Você atingiu o limite de envio do Gmail. Para contas gratuitas: 500/dia; Google Workspace: 2000/dia.

### Microsoft 365

**Problema**: "AADSTS500113: No reply address is registered for the application"
- **Causa**: O redirect URI usado na URL de autorização não está registrado no Azure Portal
- **Solução**: 
  1. Vá para Azure Portal → seu app → **Autenticação**
  2. Em **URIs de redirecionamento**, adicione o URI que você está usando:
     - `https://login.microsoftonline.com/common/oauth2/nativeclient` (recomendado)
     - OU `https://jwt.ms` (para testes)
     - OU `http://localhost:8080` (se estiver testando localmente)
  3. Clique em **Salvar**
  4. Aguarde alguns minutos e tente novamente

**Problema**: "AADSTS70011: The provided value for scope is invalid"
- **Causa**: Scope incorreto na URL de autorização
- **Solução**: Use `https://outlook.office365.com/.default` (não `SMTP.Send` ou `outlook.office.com`)
  ```
  scope=offline_access https://outlook.office365.com/.default
  ```

**Problema**: "Client is not authenticated"
- **Solução**: Execute o registro do Service Principal no Exchange Online (Passo 5 da configuração).

**Problema**: "SMTP AUTH disabled"
- **Solução**: Habilite SMTP Autenticado para a caixa de correio no Centro de Administração do Microsoft 365.

**Problema**: "Tenant ID not found"
- **Solução**: Verifique se você copiou o Tenant ID correto da página de Visão Geral do registro do app.

**Problema**: Client secret expirado
- **Solução**: Crie um novo client secret no Azure Portal e atualize a configuração no SamurEye.

### Geral

**Problema**: "Connection timeout"
- **Solução**: Verifique se a porta 587 está aberta no firewall e se a conexão TLS está habilitada.

**Problema**: Credenciais perdidas
- **Solução**: 
  - Client Secret: Não pode ser recuperado, crie um novo
  - Refresh Token: Revogue o acesso e gere um novo através do fluxo OAuth2

**Problema**: Tokens OAuth2 aparecem como `[ENCRYPTED]`
- **Solução**: Isso é normal. As credenciais são criptografadas e redactadas por segurança. Deixe os campos em branco para manter os valores atuais.

---

## Informações Técnicas

### Segurança

Todas as credenciais OAuth2 são armazenadas de forma segura:
- Criptografia usando padrão KEK (Key Encryption Key) + DEK (Data Encryption Key)
- Client Secret e Refresh Token são criptografados antes de salvar no banco de dados
- Campos sensíveis são redactados em logs de auditoria e respostas da API

### Refresh Automático de Tokens

O SamurEye renova automaticamente os access tokens usando os refresh tokens:
- **Gmail**: Usa `googleapis` para renovação automática
- **Microsoft 365**: Usa `@azure/msal-node` para renovação automática
- Access tokens são obtidos dinamicamente antes de cada envio de email
- Não é necessário intervir manualmente

### Configurações SMTP

| Provedor | Host | Porta | TLS/SSL | Auth Type |
|----------|------|-------|---------|-----------|
| Gmail | smtp.gmail.com | 587 | Sim | oauth2_gmail |
| Microsoft 365 | smtp.office365.com | 587 | Sim | oauth2_microsoft |

---

## Referências

- [Google OAuth2 Documentation](https://developers.google.com/identity/protocols/oauth2)
- [Gmail API Documentation](https://developers.google.com/gmail/api)
- [Microsoft OAuth2 Documentation](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
- [Microsoft SMTP OAuth2](https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth)

---

## Suporte

Em caso de dúvidas ou problemas não cobertos neste guia, consulte a documentação oficial dos provedores ou entre em contato com o suporte técnico.
