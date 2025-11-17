import { describe, it, expect, vi } from 'vitest';
import { expandTilde } from '../src/utils.js';
import { homedir } from 'os';
import { resolve } from 'path';

vi.mock('os');

describe('expandTilde', () => {
  const mockHomedir = '/home/testuser';

  beforeEach(() => {
    vi.mocked(homedir).mockReturnValue(mockHomedir);
  });

  it('should expand ~ to home directory', () => {
    const result = expandTilde('~');
    expect(result).toBe(mockHomedir);
  });

  it('should expand ~/path to home directory with path', () => {
    const result = expandTilde('~/Documents/file.txt');
    expect(result).toBe(resolve(mockHomedir, 'Documents/file.txt'));
  });

  it('should not expand paths without tilde', () => {
    const result = expandTilde('/absolute/path/file.txt');
    expect(result).toBe('/absolute/path/file.txt');
  });

  it('should not expand tilde in middle of path', () => {
    const result = expandTilde('/some/path/~/file.txt');
    expect(result).toBe('/some/path/~/file.txt');
  });

  it('should handle relative paths without tilde', () => {
    const result = expandTilde('./relative/path');
    expect(result).toBe('./relative/path');
  });
});