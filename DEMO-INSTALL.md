# SamurEye Demo — Guia de Instalação

Instala uma instância de demonstração do SamurEye em `/opt/samureye-demo`, servida na porta **5005** e acessível via nginx em `www.samureye.com.br/demo`.

---

## Pré-requisitos

- Debian/Ubuntu 20.04+
- Acesso root (ou sudo)
- nginx já instalado e configurado para `www.samureye.com.br`
- PostgreSQL instalado (ou será instalado automaticamente)
- Git e curl disponíveis

---

## Instalação

### 1. Baixe o script

```bash
curl -fsSL https://raw.githubusercontent.com/GruppenIT/SamurEyePlatform/main/install-demo.sh -o install-demo.sh
chmod +x install-demo.sh
```

Ou, se já tiver o repositório clonado:

```bash
cd /opt/samureye
chmod +x install-demo.sh
```

### 2. Execute a instalação

```bash
sudo ./install-demo.sh --install
```

O script irá:

1. Instalar Node.js 22 LTS (se necessário)
2. Detectar e reutilizar o PostgreSQL existente (ou instalar)
3. Criar banco `samureye_demo` e usuário `samureye_demo`
4. Clonar a branch `main` em `/opt/samureye-demo`
5. Instalar dependências npm
6. Compilar o frontend com o base path `/demo/`
7. Compilar o backend
8. Executar migrations
9. Criar usuário admin de demonstração
10. Popular o banco com dados de demonstração
11. Criar o serviço systemd `samureye-demo`
12. Gerar o snippet nginx

### 3. Configure o nginx

Após a instalação, o script gera o arquivo `/etc/nginx/snippets/samureye-demo.conf`.

Adicione a diretiva `include` dentro do bloco `server {}` do seu nginx (o mesmo que serve `www.samureye.com.br`):

```nginx
server {
    server_name www.samureye.com.br;

    # ... sua configuração existente ...

    include snippets/samureye-demo.conf;
}
```

Teste e recarregue o nginx:

```bash
nginx -t && systemctl reload nginx
```

### 4. Acesse o demo

```
https://www.samureye.com.br/demo
```

| Campo | Valor |
|---|---|
| E-mail | `demo@samureye.com.br` |
| Senha | `Demo@2024!` |

---

## Outros comandos

### Repopular dados de demonstração

Restaura todos os dados fictícios sem reinstalar a aplicação:

```bash
sudo ./install-demo.sh --seed
```

### Atualizar para a versão mais recente

Puxa a branch `main`, reconstrói e reinicia (preserva banco e `.env`):

```bash
sudo ./install-demo.sh --update
```

### Verificar status

```bash
sudo ./install-demo.sh --status

# Ou diretamente:
systemctl status samureye-demo
```

### Logs

```bash
tail -f /var/log/samureye-demo/app.log
tail -f /var/log/samureye-demo/error.log
```

---

## O que o demo inclui

| Categoria | Dados |
|---|---|
| Ativos | 9 (hosts, web apps, ranges de rede) |
| Hosts | 8 servidores e estações |
| Jornadas | 5 (uma de cada tipo) |
| Endpoints de API descobertos | 16 |
| Jobs executados | 10 (histórico por jornada) |
| Ameaças | 13+ pai + filhas com recomendações |
| Agendamentos | 5 (um por jornada) |

## Diferenças em relação à instância real

- Jornadas **não executam** — fila de jobs desabilitada
- E-mails **não são enviados**
- Banner âmbar visível em todas as páginas indicando modo demo
- Banco de dados isolado (`samureye_demo`)

---

## Desinstalar

```bash
sudo systemctl stop samureye-demo
sudo systemctl disable samureye-demo
sudo rm /etc/systemd/system/samureye-demo.service
sudo systemctl daemon-reload

sudo rm -rf /opt/samureye-demo /var/log/samureye-demo
sudo rm -f /etc/nginx/snippets/samureye-demo.conf

sudo -u postgres dropdb samureye_demo
sudo -u postgres dropuser samureye_demo
sudo userdel samureye-demo
```
