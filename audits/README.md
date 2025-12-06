# Webbuf Security Audits

This directory contains security audit reports for the webbuf cryptographic
library.

## Audit Philosophy

The webbuf library takes security seriously. Each package undergoes rigorous
testing against:

- **Official test vectors** from standards bodies (NIST, RFC, etc.)
- **Cross-implementation verification** against trusted libraries
- **Web Crypto API interoperability** for browser-native validation
- **Property-based testing** for edge cases and security properties

## Audit Reports

| Date | Report | Packages | Tests | Bugs Found |
|------|--------|----------|-------|------------|
| December 2024 | [2024-12-audit.md](./2024-12-audit.md) | 13 | 598 | 2 (fixed) |

## Running Audit Tests

All audit tests are located in `test/audit.test.ts` within each package
directory. To run all tests:

```bash
# Run tests for a specific package
cd ts/npm-webbuf-sha256
npm test

# Run all tests across the monorepo
pnpm test
```

## Reporting Security Issues

If you discover a security vulnerability, please report it responsibly by
emailing security@identellica.com rather than opening a public issue.

## Contributing to Audits

When adding new packages or modifying existing cryptographic code:

1. Add comprehensive audit tests in `test/audit.test.ts`
2. Include official test vectors where available
3. Add cross-implementation tests against trusted libraries
4. Update the relevant audit document
5. Document any bugs found and their fixes
