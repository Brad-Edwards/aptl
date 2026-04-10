

import { homedir } from 'node:os';
import { resolve } from 'node:path';

/**
 * Expand tilde (~) in file paths to the user's home directory
 */
export function expandTilde(filePath: string): string {
  if (filePath === '~') {
    return homedir();
  }
  if (filePath.startsWith('~/')) {
    return resolve(homedir(), filePath.slice(2));
  }
  return filePath;
}
