# mimocode-plusplus

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MiMoCode](https://img.shields.io/badge/MiMoCode-%3E%3D0.38.0-blue.svg)](https://github.com/nicepkg/mimocode)
[![Tests](https://img.shields.io/badge/tests-53%20passing-brightgreen.svg)](#tests)
[![Based on](https://img.shields.io/badge/based%20on-opencode--plusplus-blue.svg)](https://github.com/whut09/opencode-plusplus)

> Your AI agent runs `rm -rf /` → data gone. This hook blocks it before execution.

Command guard, path guard, output sanitizer, evidence recording, idle-verify debounce, and policy engine — all via MiMoCode file hooks. Based on [whut09/opencode-plusplus](https://github.com/whut09/opencode-plusplus) (108 ⭐) sidecar system.

## Quick Start

```bash
git clone https://github.com/Cipher208/mimocode-plusplus-v2.git /tmp/mimocode-plusplus
mkdir -p ~/.config/mimocode/hooks
cp /tmp/mimocode-plusplus/hooks/plusplus.ts ~/.config/mimocode/hooks/
```

Restart MiMoCode. Done — your agent is now protected.

## Features

### Command Guard

Blocks dangerous commands before execution:

| Pattern | Blocked | Why |
|---------|---------|-----|
| `rm -rf /` | ✅ | Destructive recursive remove |
| `git reset --hard` | ✅ | Hard git reset |
| `git push --force` | ✅ | Force push |
| `curl ... \| sh` | ✅ | Remote script pipe to shell |
| `chmod -R 777` | ✅ | World-writable permissions |
| `docker system prune -a` | ✅ | Prune all resources |
| Unknown npm script | ✅ | Script not in package.json |
| Unknown make target | ✅ | Target not in Makefile |

### Path Guard

Blocks access to sensitive files and directories:

| Pattern | Severity | Why |
|---------|----------|-----|
| `.env*`, `credentials.json` | 🚫 Blocker | Secrets |
| `.ssh/`, `.gnupg/`, `id_rsa` | 🚫 Blocker | Keys |
| `.kube/config`, `.npmrc` | 🚫 Blocker | Credentials |
| `node_modules/`, `dist/`, `coverage/` | ⚠️ Warning | Generated |

### Output Sanitizer

Automatically redacts sensitive data from tool output:

- GitHub PATs (`ghp_...`)
- OpenAI API keys (`sk-...T3BlbkFJ...`)
- Anthropic API keys (`sk-ant-...`)
- AWS access keys (`AKIA...`)
- JWT tokens, Bearer tokens, private keys

### Evidence Recording

Records every tool execution to `.agent-context/sidecar/evidence.jsonl`:

- Tool name and command
- Exit code
- stdout/stderr SHA-256 hashes
- Redaction status
- Timestamp

### Idle-Verify Debounce

After any write/edit operation, automatically runs policy check 5 seconds later:

1. Tool executes → records evidence
2. Write/edit detected → marks repo dirty → starts 5s timer
3. No more edits for 5s → runs policy check
4. Writes report to `.agent-context/sidecar/policy-report.json`

### Policy Engine

Three-level verification:

| Level | What it checks | Action |
|-------|---------------|--------|
| **Forbidden** | Generated files, build output changed directly | Block |
| **Risk** | Sensitive paths, large diffs (10+ files) | Warn |
| **Required** | Test evidence after source changes | Require |

## Configuration

Set the log file for debugging:

```bash
export OPENCPP_LOG=/tmp/plusplus.log
```

## How It Works

```
Agent calls: rm -rf /
  ↓ tool.execute.before
  Command guard: BLOCKED
  ↓ (execution prevented)

Agent writes: .env file
  ↓ tool.execute.before
  Path guard: BLOCKED
  ↓ (write prevented)

Agent edits: src/index.ts
  ↓ tool.execute.after
  Evidence recorded
  ↓ mark dirty, start 5s timer
  ↓
  ↓ (5s idle)
  ↓ Policy check runs
  ↓ Writes report to .agent-context/sidecar/
```

## Tests

53 tests covering all functionality:

```bash
cd tests && node --experimental-strip-types plusplus.test.ts
```

- 18 command guard tests (dangerous + safe patterns)
- 15 path guard tests (secret + protected + allowed)
- 8 output sanitizer tests (redaction patterns)
- 3 hash tests (determinism, uniqueness)
- 2 policy engine tests (generated files, build output)
- 7 integration tests (hook exports, blocking, allowing)

## File Structure

```
.
├── hooks/
│   └── plusplus.ts          # The hook (install this)
├── tests/
│   └── plusplus.test.ts     # 53 tests
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── SECURITY.md
├── LICENSE
└── FUTURE_PLAN.md           # Planned features
```

## Future Plans

See [FUTURE_PLAN.md](FUTURE_PLAN.md) for planned features from opencode-plusplus.

## Based On

Adapted from [whut09/opencode-plusplus](https://github.com/whut09/opencode-plusplus) (108 ⭐) sidecar system for MiMoCode file hooks.

Key differences:
- OpenCode: `tool.execute.before`/`after` hooks → MiMoCode: file hooks (`hooks/*.ts`)
- OpenCode: external plugins → MiMoCode: file hooks (external plugins don't work)
- OpenCode: CLI-based sidecar → MiMoCode: single self-contained hook file

## License

MIT
