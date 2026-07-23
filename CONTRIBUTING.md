# Contributing

Thanks for your interest in contributing!

## Quick Start

1. Fork the repository
2. Clone your fork
3. Create a branch: `git checkout -b feature/my-feature`
4. Make your changes
5. Run tests: `cd tests && node --experimental-strip-types plusplus.test.ts`
6. Commit: `git commit -m "feat: add X"`
7. Push: `git push origin feature/my-feature`
8. Open a Pull Request

## Development

### Testing

```bash
cd tests && node --experimental-strip-types plusplus.test.ts
```

### Adding features

1. Add logic to `hooks/plusplus.ts`
2. Add tests to `tests/plusplus.test.ts`
3. Update README.md if adding user-facing features
4. Update CHANGELOG.md

### Code Style

- TypeScript
- No external dependencies (hook must be self-contained)
- Use `writeFileSync` for debugging, not `console.log`
- Keep functions focused — one responsibility each

## Pull Request Guidelines

- Keep changes focused — one feature/fix per PR
- All tests must pass
- Update documentation if needed
- Follow existing code style

## Reporting Issues

Use [GitHub Issues](https://github.com/Cipher208/mimocode-plusplus-v2/issues) for bug reports and feature requests.

For security vulnerabilities, see [SECURITY.md](SECURITY.md).
