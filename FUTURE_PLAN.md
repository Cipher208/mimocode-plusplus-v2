# Future Plan

Features from [whut09/opencode-plusplus](https://github.com/whut09/opencode-plusplus) that are planned but currently too complex for MiMoCode file hooks.

## Phase 2 — Medium Effort

### 1. Full Incremental Verifier

**Source:** `sidecar-incremental-verifier.ts` (5.8K)

Currently we have a simplified policy engine. The full version from opencode-plusplus runs 6 guard types:

- Contracts validation
- Hallucination guard
- Regression guard
- Change impact report
- Test selection
- Policy engine

**What's needed:**
- ContextPackage abstraction (file indexing, dependency graph)
- Execution trace system (step tracking, evidence linking)
- Guard result aggregation

**Blocker:** Requires a file indexer that builds a dependency graph. Without it, guards can't reason about cross-file impacts.

### 2. Hallucination Guard

**Source:** `guards/hallucination.ts`

Detects when the agent references things that don't exist:

- Missing files referenced in code/diff
- Missing npm scripts referenced in trace
- Missing package dependencies
- Missing named import symbols
- Missing env config keys
- Missing local import paths

**What's needed:**
- File existence checker (scan project for referenced files)
- Package.json parser (check scripts and dependencies)
- Import resolution (resolve relative/aliased imports)

**Complexity:** Medium. Each check is independent and can be implemented as a standalone function.

### 3. Regression Guard

**Source:** `guards/regression.ts`

Matches changed files against known issues:

- Known fragile modules
- Previous fix history
- Anti-regression test mapping

**What's needed:**
- Regression memory file format (`.agent-context/regression/*.json`)
- Pattern matching against changed files
- Test evidence verification

**Complexity:** Medium. The memory format is simple JSON, but needs population from past sessions.

### 4. Test Selection

**Source:** `outputs/test-selector.ts`

Intelligently selects which tests to run based on changed files:

- File-to-test mapping
- Test confidence scoring
- Minimal test set calculation

**What's needed:**
- Test file discovery (find `*.test.ts`, `*.spec.ts`)
- Import/dependency graph to map source → test
- Configuration for custom test patterns

**Complexity:** Medium. Works well for TypeScript/JS projects with standard naming.

### 5. Change Impact Analysis

**Source:** `outputs/impact.ts`

Calculates how many files are affected by a change:

- Direct changes
- Import chain analysis
- Dependency graph traversal
- Risk scoring

**What's needed:**
- File indexer with import/dependency tracking
- Graph traversal algorithm
- Risk scoring model

**Complexity:** Medium-High. Requires the file indexer from Phase 3.

### 6. Report Renderer

**Source:** `sidecar-report-renderer.ts` (5.2K)

Renders verification results as formatted markdown:

- Command check results
- Tool execution records
- Verification reports
- Policy findings

**What's needed:**
- Markdown template system
- Severity-based formatting
- Evidence linking

**Complexity:** Low. Pure formatting, no external dependencies.

## Phase 3 — High Effort

### 7. Full Policy Engine

**Source:** `harness/verification-plane/policy-engine.ts`

The complete policy engine with all guard types:

- Forbidden: generated source, build output, contract violations
- Risk: sensitive paths, large diffs, high impact, manual test evidence
- Required: test evidence, contract validation, context freshness, regression tests

**What's needed:**
- ContextPackage (full file indexing)
- All 6 guard implementations
- Contract validation system
- Freshness/drift detection
- Evidence satisfaction checking

**Complexity:** High. This is the core of opencode-plusplus and depends on almost everything else.

### 8. Context Package Builder

**Source:** `core/context-builder.ts`

Builds a comprehensive context of the repository:

- File discovery and classification
- Import/dependency graph
- Module summaries
- Symbol indexing

**What's needed:**
- Multi-language file scanner (TS, JS, Python, Rust, Go)
- Import resolver with alias support
- Dependency graph builder
- Module summarizer

**Complexity:** High. This is the foundation for all guard-based features.

### 9. Contract Validation

**Source:** `outputs/contract-validator.ts`

Validates that code changes respect architectural contracts:

- API contracts (function signatures)
- Interface contracts (type definitions)
- Configuration contracts (env vars, config files)

**What's needed:**
- Contract definition format
- Contract extraction from code
- Contract comparison (before/after)

**Complexity:** High. Requires type analysis and code understanding.

### 10. MCP Server Tools

**Source:** `mcp/server.ts`

13 MCP tools for agent integration:

- `opencode_plusplus_build` — Scan repo, write context
- `opencode_plusplus_plan` — Task plan with modules/files
- `opencode_plusplus_pack` — Write task context pack
- `opencode_plusplus_retrieve` — Search repo context
- `opencode_plusplus_tests` — Select tests for diff
- `opencode_plusplus_impact` — Change impact analysis
- `opencode_plusplus_verify` — Verify changes
- `opencode_plusplus_explain` — Explain file/module

**What's needed:**
- MCP server implementation
- ContextPackage for all query tools
- CLI adapter for MiMoCode

**Complexity:** High. Requires the full context system.

## Priority Order

1. **Report Renderer** (Low) — Quick win, improves UX
2. **Test Selection** (Medium) — High value for CI/CD
3. **Hallucination Guard** (Medium) — Prevents common agent errors
4. **Change Impact** (Medium-High) — Better code review
5. **Regression Guard** (Medium) — Prevents bug reintroduction
6. **Full Verifier** (High) — Complete guard stack
7. **Context Builder** (High) — Foundation for everything
8. **Policy Engine** (High) — Complete verification
9. **Contract Validation** (High) — Architectural safety
10. **MCP Tools** (High) — Agent integration
