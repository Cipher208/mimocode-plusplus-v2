# Changelog

All notable changes to this project will be documented in this file.

## [0.4.0] - 2026-07-23

### Fixed
- `rm` regex gaps: now covers `-rf`, `-r -f`, `--recursive --force`, `-r /` on root
- `gho_` token pattern: expanded from 36 to 36-50 chars to match real tokens
- GitHub Actions: pinned all actions to commit SHA for security
- GitHub Actions: added `permissions: contents: read` for least privilege

### Changed
- Replaced all `any` types with proper interfaces (`GuardResult`, `Finding`, `ToolInput`, `ToolOutput`, `AfterOutput`, `ToolArgs`)
- Extracted `runPolicyCheck` into 4 focused sub-functions: `checkForbiddenFiles`, `checkSensitivePaths`, `checkLargeDiff`, `checkTestEvidence`
- Reduced cyclomatic complexity from 22 to ~8
- Added `blockIf` helper to DRY up guard blocking logic
- Tests now import from hook module (no DRY violations)

### Added
- `CONTRIBUTING.md` — contributor guide
- `CODE_OF_CONDUCT.md` — community standards
- `LICENSE` — MIT license file
- `FUTURE_PLAN.md` — planned features from opencode-plusplus

## [0.3.0] - 2026-07-23

### Added
- **Idle-verify debounce** — auto-runs policy check 5s after last write/edit
- **Policy engine** — forbidden (generated/build), risk (sensitive/large diff), required (test evidence)
- **53 tests** — command guard, path guard, sanitizer, hash, policy engine, integration

### Changed
- Enhanced command guard with npm/make script validation
- Enhanced path guard with 11 secret patterns and 9 protected directories
- Improved output sanitizer with GitHub/OpenAI/Anthropic/AWS key redaction

## [0.2.0] - 2026-07-23

### Added
- Full command guard (12 dangerous patterns from opencode-plusplus)
- npm script validation (checks package.json)
- Makefile target validation
- Enhanced path guard (secret files, protected directories)
- Output sanitizer with API key/JWT/private key redaction

## [0.1.0] - 2026-07-23

### Added
- Initial release
- `tool.execute.before` hook — command guard + path guard
- `tool.execute.after` hook — evidence recording
- Dangerous command patterns (rm -rf, git reset --hard, curl|sh, etc.)
- Protected path patterns (.env, credentials, .ssh, etc.)
- Evidence recording to `.agent-context/sidecar/evidence.jsonl`
