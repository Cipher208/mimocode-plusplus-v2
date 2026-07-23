# Changelog

## [0.1.0] - 2026-07-23

### Added
- Initial release
- `tool.execute.before` hook — command guard + path guard
- `tool.execute.after` hook — evidence recording
- Dangerous command patterns (rm -rf, git reset --hard, curl|sh, etc.)
- Protected path patterns (.env, credentials, .ssh, etc.)
- Evidence recording to `.agent-context/sidecar/evidence.jsonl`
