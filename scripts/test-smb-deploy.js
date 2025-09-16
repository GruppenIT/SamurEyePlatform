#!/usr/bin/env node
/**
 * Script de teste isolado para deployment SMB
 * Uso: node scripts/test-smb-deploy.js <hostname> <username> <password> [domain]
 */

const { spawn } = require('child_process');
const fs = require('fs/promises');
const path = require('path');

async function testSMBDeploy() {
    const args = process.argv.slice(2);
    if (args.length < 3) {
        console.error('Uso: node scripts/test-smb-deploy.js <hostname> <username> <password> [domain]');
        process.exit(1);
    }

    const [hostname, username, password, domain] = args;
    const timestamp = Date.now();
    
    console.log('🔧 SamurEye - Teste SMB Deploy');
    console.log('================================');
    console.log(`📡 Target: ${hostname}`);
    console.log(`👤 User: ${domain ? `${domain}\\${username}` : username}`);
    console.log(`⏰ Timestamp: ${new Date().toISOString()}`);
    console.log('');

    try {
        // 1. Verificar se smbclient existe
        console.log('🔍 Verificando smbclient...');
        const whichResult = await executeCommand('which', ['smbclient'], 10000);
        console.log(`✅ smbclient encontrado: ${whichResult.stdout.trim()}`);

        // 2. Criar arquivo EICAR temporário
        const eicarContent = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
        const tempEicarFile = `/tmp/test_eicar_${timestamp}.txt`;
        await fs.writeFile(tempEicarFile, eicarContent, 'utf8');
        console.log(`📄 Arquivo EICAR criado: ${tempEicarFile}`);

        // 3. Criar arquivo de autenticação
        const authFile = `/tmp/smbauth_test_${timestamp}`;
        const authContent = `username=${username}\npassword=${password}` + 
                           (domain ? `\ndomain=${domain}` : '');
        await fs.writeFile(authFile, authContent, { mode: 0o600 });
        console.log(`🔐 Arquivo auth criado: ${authFile}`);

        // 4. Testar conectividade básica
        console.log('');
        console.log('🌐 Testando conectividade básica...');
        const listArgs = [`//${hostname}/C$`, '-A', authFile, '-c', 'ls'];
        console.log(`Executando: smbclient ${listArgs.join(' ')}`);
        
        const listResult = await executeCommand('smbclient', listArgs, 30000);
        if (listResult.code === 0) {
            console.log('✅ Conectividade básica OK');
            console.log('📋 Conteúdo do C$:');
            console.log(listResult.stdout.slice(0, 500) + (listResult.stdout.length > 500 ? '...' : ''));
        } else {
            console.log('❌ Erro na conectividade básica:');
            console.log('STDOUT:', listResult.stdout);
            console.log('STDERR:', listResult.stderr);
        }

        // 5. Tentar deployment do arquivo
        console.log('');
        console.log('📤 Testando deployment do arquivo EICAR...');
        const deployArgs = [
            `//${hostname}/C$`,
            '-A', authFile,
            '-c', `put "${tempEicarFile}" "Windows\\Temp\\samureye_test_${timestamp}.txt"`
        ];
        console.log(`Executando: smbclient ${deployArgs.join(' ')}`);
        
        const deployResult = await executeCommand('smbclient', deployArgs, 30000);
        console.log('');
        console.log('📊 RESULTADO DO DEPLOYMENT:');
        console.log('═══════════════════════════');
        console.log(`Exit Code: ${deployResult.code}`);
        console.log('STDOUT:', deployResult.stdout);
        console.log('STDERR:', deployResult.stderr);

        if (deployResult.code === 0) {
            console.log('✅ DEPLOYMENT COM SUCESSO!');
            
            // 6. Verificar se arquivo foi criado
            console.log('');
            console.log('🔍 Verificando se arquivo foi criado...');
            const checkArgs = [
                `//${hostname}/C$`,
                '-A', authFile,
                '-c', `ls "Windows\\Temp\\samureye_test_${timestamp}.txt"`
            ];
            
            const checkResult = await executeCommand('smbclient', checkArgs, 15000);
            if (checkResult.code === 0 && !checkResult.stderr.includes('NT_STATUS_OBJECT_NAME_NOT_FOUND')) {
                console.log('✅ Arquivo confirmado no destino!');
                
                // 7. Limpar arquivo
                console.log('');
                console.log('🧹 Limpando arquivo de teste...');
                const cleanArgs = [
                    `//${hostname}/C$`,
                    '-A', authFile,
                    '-c', `del "Windows\\Temp\\samureye_test_${timestamp}.txt"`
                ];
                
                const cleanResult = await executeCommand('smbclient', cleanArgs, 15000);
                if (cleanResult.code === 0) {
                    console.log('✅ Arquivo limpo com sucesso');
                } else {
                    console.log('⚠️ Falha na limpeza (arquivo pode ter sido removido pelo AV)');
                    console.log('STDERR:', cleanResult.stderr);
                }
            } else {
                console.log('❌ Arquivo não encontrado no destino');
                console.log('STDERR:', checkResult.stderr);
            }
            
        } else {
            console.log('❌ FALHA NO DEPLOYMENT');
            
            // Analisar erros comuns
            if (deployResult.stderr.includes('NT_STATUS_ACCESS_DENIED')) {
                console.log('');
                console.log('🔍 ANÁLISE DO ERRO NT_STATUS_ACCESS_DENIED:');
                console.log('==========================================');
                console.log('Possíveis causas:');
                console.log('1. Usuário não tem permissão de escrita no C$');
                console.log('2. Política de segurança bloqueia acesso administrativo');
                console.log('3. UAC (User Access Control) bloqueando acesso');
                console.log('4. Firewall ou antivírus bloqueando SMB');
                console.log('5. Credenciais corretas mas usuário não é admin local');
                console.log('6. Share administrativo C$ pode estar desabilitado');
                console.log('');
                console.log('💡 Sugestões:');
                console.log('- Verificar se usuário está no grupo "Administradores" da máquina');
                console.log('- Testar com share diferente (ex: ADMIN$ ao invés de C$)');
                console.log('- Verificar políticas de grupo que restringem shares administrativos');
                console.log('- Testar conectividade SMB manual: smbclient //<host>/C$ -U <user>');
            }
        }

    } catch (error) {
        console.error('❌ Erro durante teste:', error.message);
    } finally {
        // Limpeza dos arquivos temporários
        try {
            await fs.unlink(`/tmp/test_eicar_${timestamp}.txt`);
            await fs.unlink(`/tmp/smbauth_test_${timestamp}`);
            console.log('');
            console.log('🧹 Arquivos temporários limpos');
        } catch (e) {
            // Ignore cleanup errors
        }
    }
}

function executeCommand(command, args, timeout = 30000) {
    return new Promise((resolve) => {
        console.log(`[DEBUG] Executando: ${command} ${args.join(' ')}`);
        
        const child = spawn(command, args, {
            stdio: ['pipe', 'pipe', 'pipe']
        });
        
        // Implementar timeout real usando setTimeout
        const timeoutHandle = setTimeout(() => {
            child.kill('SIGKILL');
            resolve({
                code: 124, // Timeout exit code
                stdout: '',
                stderr: 'Command timed out'
            });
        }, timeout);

        let stdout = '';
        let stderr = '';

        child.stdout?.on('data', (data) => {
            stdout += data.toString();
        });

        child.stderr?.on('data', (data) => {
            stderr += data.toString();
        });

        child.on('close', (code) => {
            clearTimeout(timeoutHandle);
            resolve({
                code: code || 0,
                stdout: stdout.trim(),
                stderr: stderr.trim()
            });
        });

        child.on('error', (error) => {
            clearTimeout(timeoutHandle);
            resolve({
                code: 1,
                stdout: stdout.trim(),
                stderr: `Process error: ${error.message}`
            });
        });
    });
}

// Executar se chamado diretamente
if (require.main === module) {
    testSMBDeploy().catch(console.error);
}

module.exports = { testSMBDeploy };