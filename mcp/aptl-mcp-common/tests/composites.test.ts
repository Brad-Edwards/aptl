import { describe, it, expect } from 'vitest';
import {
  generateCompositeToolDefinitions,
  generateCompositeToolHandlers,
  compositeContextKinds,
  type CompositeTool,
} from '../src/tools/composites.js';

const serverConfig = {
  name: 'test-server',
  version: '1.0.0',
  description: 'Test - server',
  toolPrefix: 'test',
  targetName: 'Test Target',
  configKey: 'test',
};

function makeComposite(overrides: Partial<CompositeTool> = {}): CompositeTool {
  return {
    name: 'demo',
    description: 'A demo composite',
    contextKind: 'ssh',
    inputSchema: { type: 'object', properties: {} },
    handler: async () => ({ content: [{ type: 'text', text: '{}' }] }),
    ...overrides,
  };
}

describe('generateCompositeToolDefinitions', () => {
  it('prefixes the tool name with the server toolPrefix', () => {
    const defs = generateCompositeToolDefinitions(serverConfig, [makeComposite()]);
    expect(defs).toHaveLength(1);
    expect(defs[0].name).toBe('test_demo');
    expect(defs[0].description).toBe('A demo composite');
    expect(defs[0].inputSchema).toEqual({ type: 'object', properties: {} });
  });

  it('returns one definition per composite', () => {
    const defs = generateCompositeToolDefinitions(serverConfig, [
      makeComposite({ name: 'a' }),
      makeComposite({ name: 'b' }),
    ]);
    expect(defs.map((d) => d.name)).toEqual(['test_a', 'test_b']);
  });

  it('returns an empty array for no composites', () => {
    expect(generateCompositeToolDefinitions(serverConfig, [])).toEqual([]);
  });
});

describe('generateCompositeToolHandlers', () => {
  it('maps the prefixed tool name to the composite handler', async () => {
    const handler = async () => ({ content: [{ type: 'text', text: 'ok' }] });
    const handlers = generateCompositeToolHandlers(serverConfig, [makeComposite({ handler })]);
    expect(Object.keys(handlers)).toEqual(['test_demo']);
    const result = await handlers['test_demo']({}, { labConfig: {} as never });
    expect(result.content[0].text).toBe('ok');
  });
});

describe('compositeContextKinds', () => {
  it('records each composite context kind under its prefixed name', () => {
    const kinds = compositeContextKinds(serverConfig, [
      makeComposite({ name: 'ssh_only', contextKind: 'ssh' }),
      makeComposite({ name: 'api_only', contextKind: 'api' }),
      makeComposite({ name: 'both_kinds', contextKind: 'both' }),
    ]);
    expect(kinds).toEqual({
      test_ssh_only: 'ssh',
      test_api_only: 'api',
      test_both_kinds: 'both',
    });
  });
});
