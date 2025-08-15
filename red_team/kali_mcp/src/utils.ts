// SPDX-License-Identifier: BUSL-1.1

import { homedir } from 'os';
import { resolve } from 'path';

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