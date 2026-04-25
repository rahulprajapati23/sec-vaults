import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([
  globalIgnores(['dist']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      globals: globals.browser,
    },
    rules: {
      // Keep strictness but avoid blocking builds on legacy API surface typing.
      '@typescript-eslint/no-explicit-any': 'warn',
      // Vite fast-refresh rule is useful, but this codebase intentionally exports helpers with components.
      'react-refresh/only-export-components': 'off',
      // These rules are too aggressive for current stateful pages and can be incrementally re-enabled later.
      'react-hooks/set-state-in-effect': 'off',
      'react-hooks/immutability': 'off',
    },
  },
])
