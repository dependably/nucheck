module.exports = {
  testEnvironment: 'node',
  collectCoverageFrom: [
    'index.js',
    'cli.js',
    'utils/**/*.js',
    '!**/*.test.js'
  ],
  coveragePathIgnorePatterns: [
    '/node_modules/',
    '/tests/'
  ],
  testMatch: [
    '**/tests/**/*.test.js'
  ],
  testTimeout: 10000
};
