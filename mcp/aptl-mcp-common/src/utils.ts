

import { homedir } from 'os';
import { resolve } from 'path';

/**
 * Expand tilde (~) in file paths to the user's home directory.
 * The resolved path is validated to stay within the home directory
 * to prevent path traversal attacks (e.g. "~/../etc/passwd").
 */
export function expandTilde(filePath: string): string {
  if (filePath === '~') {
    return homedir();
  }
  if (filePath.startsWith('~/')) {
    const resolved = resolve(homedir(), filePath.slice(2));
    const home = homedir();
    if (!resolved.startsWith(home + '/') && resolved !== home) {
      throw new Error(`Path traversal detected: '${filePath}' resolves outside home directory`);
    }
    return resolved;
  }
  return filePath;
} 