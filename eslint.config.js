const js = require('@eslint/js');
const globals = require('globals');

// Flat config (ESLint v9+/v10). This project is CommonJS (require/module.exports),
// so sourceType is 'commonjs' rather than 'module'.
module.exports = [
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2021,
      sourceType: 'commonjs',
      globals: {
        ...globals.node,
        ...globals.es2021,
        ...globals.jest
      }
    },
    rules: {
      'no-console': 'off',
      'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      'no-useless-escape': 'off'
    }
  },
  {
    files: ['tests/**/*.js'],
    languageOptions: {
      globals: {
        ...globals.jest
      }
    }
  }
];
