# Instalação do PowerShell Core (Hotfix)

## Problema
A jornada AD Security requer **PowerShell Core (pwsh)** para executar comandos remotos via WinRM. Se o erro `spawn pwsh ENOENT` aparecer, significa que o PowerShell não está instalado.

## Solução Rápida (Para Servidores Existentes)

Execute como **root** no servidor on-premise:

### Opção 1: Via Snap (Recomendado - Mais Rápido)
```bash
sudo snap install powershell --classic

# Cria link simbólico se necessário
sudo ln -sf /snap/bin/pwsh /usr/bin/pwsh

# Verifica instalação
pwsh --version
```

### Opção 2: Via Repositório Microsoft (Alternativa)
```bash
# Detecta versão do Ubuntu
UBUNTU_VERSION=$(lsb_release -rs)

# Baixa e instala pacote Microsoft
wget -q https://packages.microsoft.com/config/ubuntu/${UBUNTU_VERSION}/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
rm packages-microsoft-prod.deb

# Atualiza e instala PowerShell
sudo apt update
sudo apt install -y powershell

# Verifica instalação
pwsh --version
```

### Reiniciar o Serviço
Após instalar o PowerShell, reinicie o serviço SamurEye:

```bash
sudo systemctl restart samureye-api
sudo systemctl status samureye-api
```

## Para Novas Instalações

O script `install.sh` foi atualizado e já instala automaticamente o PowerShell Core. Basta executar:

```bash
sudo ./install.sh
```

## Verificação

Depois de instalar, teste se o PowerShell está acessível:

```bash
which pwsh
# Deve retornar: /usr/bin/pwsh ou /snap/bin/pwsh

pwsh --version
# Deve retornar algo como: PowerShell 7.x.x
```

## Dependências Adicionais

A jornada AD Security também requer que o **WinRM** esteja habilitado e configurado nos Domain Controllers do Active Directory. Consulte a documentação da Microsoft para configurar WinRM no Windows Server.

## Referências

- [Documentação oficial do PowerShell no Ubuntu](https://learn.microsoft.com/powershell/scripting/install/install-ubuntu)
- [Configuração do WinRM no Windows](https://learn.microsoft.com/windows/win32/winrm/installation-and-configuration-for-windows-remote-management)
