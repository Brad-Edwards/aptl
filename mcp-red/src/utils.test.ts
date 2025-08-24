import { describe, it, expect } from 'vitest';
import { expandTilde } from './utils.js';
import { homedir } from 'os';

describe('expandTilde', () => {
  it('should expand tilde paths', () => {
    const result = expandTilde('~/test/path');
    expect(result).toBe(`${homedir()}/test/path`);
  });

  it('should leave absolute paths unchanged', () => {
    const absolutePath = '/absolute/path';
    const result = expandTilde(absolutePath);
    expect(result).toBe(absolutePath);
  });

  it('should handle just tilde', () => {
    const result = expandTilde('~');
    expect(result).toBe(homedir());
  });

  it('should handle empty string', () => {
    const result = expandTilde('');
    expect(result).toBe('');
  });

  it('should handle relative paths without tilde', () => {
    const relativePath = 'relative/path';
    const result = expandTilde(relativePath);
    expect(result).toBe(relativePath);
  });
}); 