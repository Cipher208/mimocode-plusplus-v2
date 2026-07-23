# mimocode-plusplus

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MiMoCode](https://img.shields.io/badge/MiMoCode-%3E%3D0.38.0-blue.svg)](https://github.com/nicepkg/mimocode)

> Command guard + path guard + evidence recording for MiMoCode via file hooks.

Blocks dangerous commands and protected paths. Records tool execution evidence. Based on [whut09/opencode-plusplus](https://github.com/whut09/opencode-plusplus) sidecar system.

## What it does

- **Command guard** — blocks `rm -rf /`, `git reset --hard`, `curl | sh`, etc.
- **Path guard** — blocks access to `.env`, `credentials.json`, `.ssh/`, etc.
- **Evidence recording** — records tool execution to `.agent-context/sidecar/evidence.jsonl`

## Installation

```bash
git clone https://github.com/Cipher208/mimocode-plusplus.git /tmp/mimocode-plusplus
mkdir -p ~/.config/mimocode/hooks
cp /tmp/mimocode-plusplus/hooks/plusplus.ts ~/.config/mimocode/hooks/
```

Then restart MiMoCode.

## Blocked commands

| Pattern | Reason |
|---------|--------|
| `rm -rf /` | Destructive recursive remove |
| `git reset --hard` | Hard git reset |
| `git clean -fd` | Removes untracked files |
| `curl ... \| sh` | Remote script pipe to shell |
| `chmod -R 777` | World-writable permissions |

## Protected paths

| Pattern | Severity |
|---------|----------|
| `.env*`, `credentials.json` | Blocker |
| `.ssh/`, `.gnupg/` | Blocker |
| `id_rsa`, `shadow`, `passwd` | Blocker |
| `.git/`, `node_modules/`, `.cache/` | Warning |

## Debugging

```bash
export OPENCPP_LOG=/tmp/opencode-plusplus.log
```

## Based on

Adapted from [whut09/opencode-plusplus](https://github.com/whut09/opencode-plusplus) (108 ⭐) sidecar system for MiMoCode file hooks.

## License

MIT
