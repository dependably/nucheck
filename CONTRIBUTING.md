# Contributing to nuget-audit

Thank you for your interest in contributing! This guide will help you get started.

## Development Setup

### Prerequisites

- Node.js 12.x or higher
- npm or yarn
- Git

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/nuget-audit.git
cd nuget-audit
```

2. Install dependencies:
```bash
npm install
```

3. Set up your GitHub token:
```bash
export GITHUB_TOKEN=your_github_personal_access_token
```

### Project Structure

```
nuget-audit/
├── index.js              # Main audit logic
├── cli.js                # CLI entry point
├── package.json          # Dependencies and scripts
├── utils/
│   ├── logger.js         # Logging utility
│   ├── cache.js          # Caching mechanism
│   ├── config.js         # Configuration loader
│   └── formatters.js     # Output formatters
├── tests/                # Test files
├── docs/                 # Documentation
└── examples/             # Example files
```

## Running Tests

Run the test suite:
```bash
npm test
```

Run tests in watch mode:
```bash
npm run test:watch
```

## Code Style Guidelines

- Use 2-space indentation
- Use camelCase for variables and functions
- Use UPPER_CASE for constants
- Add JSDoc comments to all public functions
- Keep functions focused and single-purpose
- Write descriptive variable and function names

### Example:

```javascript
/**
 * Brief description of what this function does
 * @param {string} param1 - Description of param1
 * @param {number} param2 - Description of param2
 * @returns {Promise<Object>} Description of return value
 */
async function doSomething(param1, param2) {
  // Implementation
}
```

## Making Changes

1. Create a new branch:
```bash
git checkout -b feature/your-feature-name
```

2. Make your changes and test thoroughly:
```bash
npm test
```

3. Commit your changes with clear messages:
```bash
git commit -m "Add feature: brief description"
```

4. Push to your fork:
```bash
git push origin feature/your-feature-name
```

5. Open a Pull Request with:
   - Clear description of changes
   - Reference to any related issues
   - Evidence that tests pass
   - Any breaking changes highlighted

## Testing Guidelines

- Write tests for all new features
- Ensure all existing tests pass
- Aim for >80% code coverage
- Use Jest framework (already configured)
- Mock external API calls in tests

### Test File Naming

- Test files should be in `tests/` directory
- Use `.test.js` extension
- Match the module name: `module.js` → `tests/module.test.js`

## Reporting Issues

When reporting bugs, please include:
- Node.js version
- npm version
- Exact steps to reproduce
- Expected vs actual behavior
- Your packages.config or packages.lock.json (if possible)
- Error messages and stack traces

## Feature Requests

Feature requests are welcome! Please describe:
- Use case and problem being solved
- Proposed solution
- Alternatives you've considered
- Additional context

## Documentation

- Update README.md for user-facing changes
- Update docs/API.md for API changes
- Add JSDoc comments to all functions
- Update examples if behavior changes

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions?

Feel free to open an issue with the `question` label if you need help!

Thank you for contributing to nuget-audit! 🎉
