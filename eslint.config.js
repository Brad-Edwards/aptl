// Root ESLint flat config: a NARROW per-function complexity gate for the
// TypeScript surfaces. This is the cyclomatic-complexity sibling of the Python
// `ruff-complexity` gate (ADR-010): only the core ESLint `complexity` rule is
// enabled here, a complexity guard, not a style linter. It is intentionally
// SEPARATE from the per-package ESLint configs under `mcp/mcp-red/` and
// `mcp/mcp-reverse/` (flat config loads a single config file, so those do not
// cascade into this one) and from the advisory, new-code-scoped SonarCloud
// scan.
//
// Parser loading is portable across whatever Node the CI runner ships. The
// `ts-complexity` pre-commit hook runs this through pre-commit's isolated
// `language: node` environment, which exports `NODE_PATH=<env>/lib/node_modules`
// but does NOT install a repo-root `node_modules`. `require.resolve` honours
// `NODE_PATH`, so it finds each pinned parser in the hook env; importing the
// resolved absolute path then loads ESM-only parsers (svelte-eslint-parser) on
// any Node >= 18 without relying on `require(esm)` (a bare `require()` of an ESM
// package needs Node >= 22.12, which the no-setup-node CI job cannot guarantee).
// ESLint awaits a config module that exports a promise, so the async load below
// is a supported flat-config form.
const { pathToFileURL } = require('node:url');

async function loadParser(pkg) {
  const mod = await import(pathToFileURL(require.resolve(pkg)).href);
  return mod.default ?? mod;
}

// Single source of truth for the threshold. Matches the Python side
// (`pyproject` `[tool.ruff.lint.mccabe] max-complexity = 15`) and SonarCloud's
// default. Ratchet DOWN as the backlog below shrinks; never up.
const MAX_COMPLEXITY = 15;

module.exports = (async () => {
  const tsParser = await loadParser('@typescript-eslint/parser');
  const svelteParser = await loadParser('svelte-eslint-parser');

  const complexity = { complexity: ['error', { max: MAX_COMPLEXITY }] };

  return [
    {
      // Global ignores: build output, dependencies, generated SvelteKit types,
      // and test files (tests legitimately carry long table-driven blocks).
      ignores: [
        '**/build/**',
        '**/dist/**',
        '**/node_modules/**',
        'web/.svelte-kit/**',
        '**/*.test.ts',
        '**/*.spec.ts',
        '**/tests/**',
      ],
    },
    {
      // mcp/* server sources + web TypeScript modules.
      files: ['mcp/*/src/**/*.ts', 'web/src/**/*.ts'],
      languageOptions: { parser: tsParser, ecmaVersion: 2023, sourceType: 'module' },
      // Ignore inline `eslint-disable` comments. This config is a single-rule
      // gate, so it intentionally does not load the `@typescript-eslint` *rules*
      // plugin, only the parser. Source files written for the per-package
      // configs carry inline directives for plugin rules this config does not
      // define (for example `@typescript-eslint/no-explicit-any`); without this,
      // ESLint errors on every such "unknown rule" directive. It also keeps the
      // gate central and tamper-resistant: `complexity` cannot be silenced with
      // an inline `// eslint-disable`, so exemptions live only in this file.
      linterOptions: { noInlineConfig: true },
      rules: complexity,
    },
    {
      // Svelte single-file components: functions in `<script lang="ts">` blocks
      // are first-class scope, not a TS-only afterthought.
      files: ['web/src/**/*.svelte'],
      languageOptions: {
        parser: svelteParser,
        parserOptions: { parser: tsParser },
        ecmaVersion: 2023,
        sourceType: 'module',
      },
      linterOptions: { noInlineConfig: true },
      rules: complexity,
    },
  ];
})();
