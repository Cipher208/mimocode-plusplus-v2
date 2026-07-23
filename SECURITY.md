# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.4.x   | Yes       |
| 0.3.x   | Yes       |
| 0.2.x   | No        |
| 0.1.x   | No        |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Use [GitHub Private Vulnerability Reporting](https://github.com/Cipher208/mimocode-plusplus-v2/security).

## Scope

This project is a MiMoCode file hook (~300 lines). Security concerns are limited to:

- **Command injection** — The hook rewrites shell commands. Ensure rewrite rules don't introduce injection vectors.
- **Path traversal** — The hook blocks protected paths. Ensure patterns can't be bypassed.
- **Output sanitizer** — Redacts sensitive data. Ensure patterns don't miss real tokens.
- **File system access** — Evidence recording writes to `.agent-context/sidecar/`. Ensure the path is safe.

## Response Time

We aim to respond to security reports within 48 hours.
