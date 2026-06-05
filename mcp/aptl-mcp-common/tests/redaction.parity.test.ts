/**
 * Cross-language parity gate for the redaction layer (issue #386).
 *
 * The shared corpus at `tests/fixtures/redaction_parity_corpus.json` (repo
 * root) is consumed by BOTH this vitest module and the Python
 * `tests/test_redaction_parity.py`. Each case pins an input to its expected
 * redacted output; the TypeScript and Python redactors must each reproduce it
 * exactly. If the two ~950-LOC hand-maintained implementations' secret
 * patterns drift apart, one side's parity test fails — closing the silent
 * divergence hazard (ARCH-386-01 redact-05 / dup-01) that ADR-035 forbids
 * (no second redaction taxonomy).
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { redact } from '../src/redaction.js';

interface ParityCase {
  name: string;
  input: unknown;
  expected: unknown;
}

const here = dirname(fileURLToPath(import.meta.url));
// tests/ -> aptl-mcp-common/ -> mcp/ -> repo root, then tests/fixtures.
const corpusPath = join(
  here,
  '..',
  '..',
  '..',
  'tests',
  'fixtures',
  'redaction_parity_corpus.json',
);
const corpus = JSON.parse(readFileSync(corpusPath, 'utf-8')) as ParityCase[];

describe('redaction cross-language parity corpus (issue #386)', () => {
  it('corpus is non-empty', () => {
    // Guard against a truncated/empty fixture silently passing the gate.
    expect(corpus.length).toBeGreaterThanOrEqual(40);
  });

  for (const testCase of corpus) {
    it(testCase.name, () => {
      expect(redact(testCase.input)).toEqual(testCase.expected);
    });
  }
});
