import eslint from '@eslint/js';
import prettier from 'eslint-config-prettier';
import security from 'eslint-plugin-security';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  eslint.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  {
    plugins: { security },
    rules: {
      ...security.configs.recommended.rules,
      'no-console': 'error',
    },
  },
  prettier,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  {
    // packages/frontend is a Next.js app with its own eslint.config.mjs (eslint-config-next,
    // JSX/React rules) and its own tsconfig.json that deliberately doesn't extend
    // tsconfig.base.json (Next.js needs `moduleResolution: "bundler"` and DOM/JSX support this
    // config's NodeNext-resolution, backend-focused ruleset isn't set up for) — linted
    // separately via `pnpm --filter @janus/frontend lint`, chained into the root `lint` script.
    ignores: [
      '**/dist/**',
      '**/node_modules/**',
      '**/generated/**',
      'eslint.config.js',
      'vitest.config.ts',
      '**/prisma.config.ts',
      'packages/frontend/**',
      // Nested git worktrees (e.g. from a spawned background session) are independent
      // checkouts with their own (possibly absent) node_modules — ESLint's project service
      // can't type-check them from here, and they aren't part of this workspace's source.
      '.claude/worktrees/**',
    ],
  },
);
