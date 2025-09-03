import { describe, it, expect } from 'vitest';
import { 
  createShellFormatter, 
  BashShellFormatter, 
  PowerShellFormatter,
  CmdShellFormatter,
  ShellType 
} from '../src/shells.js';

describe('Shell Formatters', () => {
  describe('BashShellFormatter', () => {
    const formatter = new BashShellFormatter();

    it('should format command with delimiters correctly', () => {
      const command = 'ls -la';
      const startDelimiter = 'START_123';
      const endDelimiter = 'END_123';
      
      const result = formatter.formatCommandWithDelimiters(command, startDelimiter, endDelimiter);
      expect(result).toBe('echo "START_123"; ls -la; echo "END_123:$?"');
    });

    it('should handle commands with quotes', () => {
      const command = 'echo "hello world"';
      const startDelimiter = 'START_123';
      const endDelimiter = 'END_123';
      
      const result = formatter.formatCommandWithDelimiters(command, startDelimiter, endDelimiter);
      expect(result).toBe('echo "START_123"; echo "hello world"; echo "END_123:$?"');
    });

    it('should return correct keep-alive command', () => {
      expect(formatter.getKeepAliveCommand()).toBe('\n');
    });

    it('should parse exit code from output', () => {
      const output = 'some output\nEND_123:0\nmore output';
      expect(formatter.parseExitCode(output, 'END_123')).toBe(0);
      
      const failedOutput = 'some output\nEND_123:1\nmore output';
      expect(formatter.parseExitCode(failedOutput, 'END_123')).toBe(1);
      
      const noCodeOutput = 'some output without exit code';
      expect(formatter.parseExitCode(noCodeOutput, 'END_123')).toBeNull();
    });

    it('should get shell name', () => {
      expect(formatter.getShellName()).toBe('bash');
    });
  });

  describe('PowerShellFormatter', () => {
    const formatter = new PowerShellFormatter();

    it('should format command with delimiters correctly', () => {
      const command = 'Get-ChildItem';
      const startDelimiter = 'START_123';
      const endDelimiter = 'END_123';
      
      const result = formatter.formatCommandWithDelimiters(command, startDelimiter, endDelimiter);
      expect(result).toBe('Write-Output "START_123"; Get-ChildItem; Write-Output "END_123:$LASTEXITCODE"');
    });

    it('should handle commands with quotes', () => {
      const command = 'Write-Host "hello world"';
      const startDelimiter = 'START_123';
      const endDelimiter = 'END_123';
      
      const result = formatter.formatCommandWithDelimiters(command, startDelimiter, endDelimiter);
      expect(result).toBe('Write-Output "START_123"; Write-Host "hello world"; Write-Output "END_123:$LASTEXITCODE"');
    });

    it('should return correct keep-alive command', () => {
      expect(formatter.getKeepAliveCommand()).toBe('Write-Output ""\n');
    });

    it('should parse exit code from output', () => {
      const output = 'some output\nEND_123:0\nmore output';
      expect(formatter.parseExitCode(output, 'END_123')).toBe(0);
      
      const failedOutput = 'some output\nEND_123:1\nmore output';
      expect(formatter.parseExitCode(failedOutput, 'END_123')).toBe(1);
      
      const noCodeOutput = 'some output without exit code';
      expect(formatter.parseExitCode(noCodeOutput, 'END_123')).toBeNull();
    });

    it('should get shell name', () => {
      expect(formatter.getShellName()).toBe('powershell');
    });
  });

  describe('CmdShellFormatter', () => {
    const formatter = new CmdShellFormatter();

    it('should format command with delimiters correctly', () => {
      const command = 'dir';
      const startDelimiter = 'START_123';
      const endDelimiter = 'END_123';
      
      const result = formatter.formatCommandWithDelimiters(command, startDelimiter, endDelimiter);
      expect(result).toBe('echo START_123 & dir & echo %ERRORLEVEL% > NUL & echo END_123:%ERRORLEVEL%');
    });

    it('should handle complex commands', () => {
      const command = 'cd C:\\Users && dir';
      const startDelimiter = 'START_123';
      const endDelimiter = 'END_123';
      
      const result = formatter.formatCommandWithDelimiters(command, startDelimiter, endDelimiter);
      expect(result).toBe('echo START_123 & cd C:\\Users && dir & echo %ERRORLEVEL% > NUL & echo END_123:%ERRORLEVEL%');
    });

    it('should return correct keep-alive command', () => {
      expect(formatter.getKeepAliveCommand()).toBe('echo.\n');
    });

    it('should parse exit code from output', () => {
      const output = 'some output\nEND_123:0\nmore output';
      expect(formatter.parseExitCode(output, 'END_123')).toBe(0);
      
      const failedOutput = 'some output\nEND_123:1\nmore output';
      expect(formatter.parseExitCode(failedOutput, 'END_123')).toBe(1);
      
      const noCodeOutput = 'some output without exit code';
      expect(formatter.parseExitCode(noCodeOutput, 'END_123')).toBeNull();
    });

    it('should get shell name', () => {
      expect(formatter.getShellName()).toBe('cmd');
    });
  });

  describe('createShellFormatter', () => {
    it('should create BashShellFormatter by default', () => {
      const formatter = createShellFormatter();
      expect(formatter).toBeInstanceOf(BashShellFormatter);
      expect(formatter.getShellName()).toBe('bash');
    });

    it('should create BashShellFormatter for bash type', () => {
      const formatter = createShellFormatter('bash');
      expect(formatter).toBeInstanceOf(BashShellFormatter);
    });

    it('should create BashShellFormatter for sh type', () => {
      const formatter = createShellFormatter('sh');
      expect(formatter).toBeInstanceOf(BashShellFormatter);
      expect(formatter.getShellName()).toBe('sh');
    });

    it('should create PowerShellFormatter for powershell type', () => {
      const formatter = createShellFormatter('powershell');
      expect(formatter).toBeInstanceOf(PowerShellFormatter);
    });

    it('should create CmdShellFormatter for cmd type', () => {
      const formatter = createShellFormatter('cmd');
      expect(formatter).toBeInstanceOf(CmdShellFormatter);
    });

    it('should handle unknown shell types by defaulting to bash', () => {
      const formatter = createShellFormatter('unknown' as ShellType);
      expect(formatter).toBeInstanceOf(BashShellFormatter);
    });
  });

  describe('Shell-specific edge cases', () => {
    describe('PowerShell special cases', () => {
      const formatter = new PowerShellFormatter();

      it('should handle PowerShell special variables in commands', () => {
        const command = 'Get-Process | Where-Object {$_.CPU -gt 100}';
        const startDelimiter = 'START_123';
        const endDelimiter = 'END_123';
        
        const result = formatter.formatCommandWithDelimiters(command, startDelimiter, endDelimiter);
        expect(result).toContain('Get-Process | Where-Object {$_.CPU -gt 100}');
      });

      it('should handle multi-line PowerShell scripts', () => {
        const command = `$processes = Get-Process
$processes | Sort-Object CPU -Descending | Select-Object -First 5`;
        const startDelimiter = 'START_123';
        const endDelimiter = 'END_123';
        
        const result = formatter.formatCommandWithDelimiters(command, startDelimiter, endDelimiter);
        expect(result).toContain('Write-Output "START_123"');
        expect(result).toContain('Write-Output "END_123:$LASTEXITCODE"');
      });
    });

    describe('CMD special cases', () => {
      const formatter = new CmdShellFormatter();

      it('should handle batch file variables', () => {
        const command = 'echo %USERNAME% %COMPUTERNAME%';
        const startDelimiter = 'START_123';
        const endDelimiter = 'END_123';
        
        const result = formatter.formatCommandWithDelimiters(command, startDelimiter, endDelimiter);
        expect(result).toContain('echo %USERNAME% %COMPUTERNAME%');
      });

      it('should handle conditional execution', () => {
        const command = 'dir C:\\ && echo Success || echo Failed';
        const startDelimiter = 'START_123';
        const endDelimiter = 'END_123';
        
        const result = formatter.formatCommandWithDelimiters(command, startDelimiter, endDelimiter);
        expect(result).toContain('dir C:\\ && echo Success || echo Failed');
      });
    });
  });
});

