#!/usr/bin/env python3
"""
SamurEye WinRM Wrapper
Executes PowerShell commands on Windows hosts via WinRM using pywinrm
"""

import sys
import json
import os
import argparse
from winrm.protocol import Protocol

def execute_winrm_command(host, username, password, script, timeout=30):
    """
    Execute PowerShell command via WinRM
    
    Args:
        host: Target Windows host (IP or hostname)
        username: Username with domain (e.g., DOMAIN\\user)
        password: User password
        script: PowerShell script to execute
        timeout: Command timeout in seconds
        
    Returns:
        dict: {
            "stdout": str,
            "stderr": str,
            "exitCode": int,
            "error": str (if connection failed)
        }
    """
    try:
        # Create WinRM protocol instance
        # read_timeout_sec must be greater than operation_timeout_sec
        endpoint = f'http://{host}:5985/wsman'
        protocol = Protocol(
            endpoint=endpoint,
            transport='ntlm',
            username=username,
            password=password,
            server_cert_validation='ignore',
            read_timeout_sec=timeout + 10,  # Adiciona margem de 10 segundos
            operation_timeout_sec=timeout
        )
        
        # Execute PowerShell command
        # Use powershell.exe with -EncodedCommand to avoid quoting issues
        import base64
        
        # Encode script to Base64 (UTF-16LE for PowerShell)
        encoded_script = base64.b64encode(script.encode('utf-16le')).decode('ascii')
        
        shell_id = protocol.open_shell()
        command_id = protocol.run_command(shell_id, 'powershell.exe', ['-NoProfile', '-EncodedCommand', encoded_script])
        
        # Get output
        stdout, stderr, status_code = protocol.get_command_output(shell_id, command_id)
        
        # Cleanup
        protocol.cleanup_command(shell_id, command_id)
        protocol.close_shell(shell_id)
        
        return {
            "stdout": stdout.decode('utf-8', errors='replace').strip(),
            "stderr": stderr.decode('utf-8', errors='replace').strip(),
            "exitCode": status_code
        }
        
    except Exception as e:
        return {
            "stdout": "",
            "stderr": "",
            "exitCode": 1,
            "error": str(e)
        }

def main():
    parser = argparse.ArgumentParser(description='Execute PowerShell via WinRM')
    parser.add_argument('--host', required=True, help='Target host')
    parser.add_argument('--username', required=True, help='Username with domain')
    parser.add_argument('--script', required=True, help='PowerShell script')
    parser.add_argument('--timeout', type=int, default=30, help='Timeout in seconds')
    parser.add_argument('--password-stdin', action='store_true', help='Read password from stdin')
    
    args = parser.parse_args()
    
    # Read password from stdin for security (prevents exposure in ps/proc)
    if args.password_stdin:
        password = sys.stdin.readline().strip()
    else:
        # Fallback to environment variable
        password = os.environ.get('WINRM_PASSWORD', '')
    
    if not password:
        print(json.dumps({
            "stdout": "",
            "stderr": "Password not provided via stdin or WINRM_PASSWORD env var",
            "exitCode": 1,
            "error": "Missing password"
        }))
        sys.exit(1)
    
    # Execute command
    result = execute_winrm_command(
        host=args.host,
        username=args.username,
        password=password,
        script=args.script,
        timeout=args.timeout
    )
    
    # Output JSON result
    print(json.dumps(result, ensure_ascii=False))
    
    # Exit with command exit code
    sys.exit(result.get('exitCode', 1))

if __name__ == '__main__':
    main()
