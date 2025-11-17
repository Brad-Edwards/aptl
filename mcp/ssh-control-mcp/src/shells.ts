/**
 * Shell-specific command formatting for cross-platform SSH session support
 */

export type ShellType = 'bash' | 'sh' | 'powershell' | 'cmd';

export interface ShellFormatter {
  formatCommandWithDelimiters(command: string, startDelimiter: string, endDelimiter: string): string;
  getKeepAliveCommand(): string;
  parseExitCode(output: string, endDelimiter: string): number | null;
  getShellName(): string;
}

/**
 * Formatter for Bash and sh shells (Linux/Unix)
 */
export class BashShellFormatter implements ShellFormatter {
  private shellName: string;

  constructor(shellName: string = 'bash') {
    this.shellName = shellName;
  }

  formatCommandWithDelimiters(command: string, startDelimiter: string, endDelimiter: string): string {
    // Use semicolons for command chaining in bash/sh
    return `echo "${startDelimiter}"; ${command}; echo "${endDelimiter}:$?"`;
  }
  
  getKeepAliveCommand(): string {
    // Simple newline for bash keep-alive
    return '\n';
  }
  
  parseExitCode(output: string, endDelimiter: string): number | null {
    const pattern = `${endDelimiter}:(\\d+)`;
    const match = output.match(new RegExp(pattern));
    
    if (match && match[1]) {
      return parseInt(match[1], 10);
    }
    
    return null;
  }

  getShellName(): string {
    return this.shellName;
  }
}

/**
 * Formatter for PowerShell (Windows)
 */
export class PowerShellFormatter implements ShellFormatter {
  formatCommandWithDelimiters(command: string, startDelimiter: string, endDelimiter: string): string {
    // PowerShell uses $LASTEXITCODE for the exit code of the last command
    // Use semicolons for command separation
    return `Write-Output "${startDelimiter}"; ${command}; Write-Output "${endDelimiter}:$LASTEXITCODE"`;
  }
  
  getKeepAliveCommand(): string {
    // PowerShell keep-alive with empty output
    return 'Write-Output ""\n';
  }
  
  parseExitCode(output: string, endDelimiter: string): number | null {
    const pattern = `${endDelimiter}:(\\d+)`;
    const match = output.match(new RegExp(pattern));
    
    if (match && match[1]) {
      return parseInt(match[1], 10);
    }
    
    return null;
  }

  getShellName(): string {
    return 'powershell';
  }
}

/**
 * Formatter for Windows Command Prompt (cmd.exe)
 */
export class CmdShellFormatter implements ShellFormatter {
  formatCommandWithDelimiters(command: string, startDelimiter: string, endDelimiter: string): string {
    // CMD uses & for command chaining (always executes next command)
    // %ERRORLEVEL% contains the exit code
    // We need to capture ERRORLEVEL immediately after the command
    // The echo %ERRORLEVEL% > NUL is to force evaluation of ERRORLEVEL before the final echo
    return `echo ${startDelimiter} & ${command} & echo %ERRORLEVEL% > NUL & echo ${endDelimiter}:%ERRORLEVEL%`;
  }
  
  getKeepAliveCommand(): string {
    // CMD keep-alive with echo. (echo with period for empty line)
    return 'echo.\n';
  }
  
  parseExitCode(output: string, endDelimiter: string): number | null {
    const pattern = `${endDelimiter}:(\\d+)`;
    const match = output.match(new RegExp(pattern));
    
    if (match && match[1]) {
      return parseInt(match[1], 10);
    }
    
    return null;
  }

  getShellName(): string {
    return 'cmd';
  }
}

/**
 * Factory function to create the appropriate shell formatter
 */
export function createShellFormatter(shellType: ShellType = 'bash'): ShellFormatter {
  switch (shellType) {
    case 'powershell':
      return new PowerShellFormatter();
    case 'cmd':
      return new CmdShellFormatter();
    case 'sh':
      return new BashShellFormatter('sh');
    case 'bash':
    default:
      return new BashShellFormatter('bash');
  }
}

