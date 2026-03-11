# Instrucoes para Geracao e Verificacao do Hash SHA-512

O hash SHA-512 serve como prova de integridade do pacote de deposito.
Ele garante que o conteudo do ZIP nao foi alterado apos a geracao.

## Gerar o hash

### Linux / macOS

```bash
sha512sum SamurEye_Deposito_INPI.zip > resumo_hash_sha512.txt
```

### Windows (PowerShell)

```powershell
Get-FileHash -Algorithm SHA512 SamurEye_Deposito_INPI.zip | Format-List
```

### Windows (CertUtil)

```cmd
certutil -hashfile SamurEye_Deposito_INPI.zip SHA512 > resumo_hash_sha512.txt
```

## Verificar o hash

### Linux / macOS

```bash
sha512sum -c resumo_hash_sha512.txt
```

O comando deve retornar `SamurEye_Deposito_INPI.zip: OK` se o arquivo estiver integro.

## Formato do arquivo resumo_hash_sha512.txt

O arquivo contem uma unica linha no formato:

```
<hash_sha512_hex>  SamurEye_Deposito_INPI.zip
```
