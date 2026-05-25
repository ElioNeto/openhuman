# OpenHuman

**React + Tauri v2 desktop app with a Rust core (JSON-RPC/CLI) embedded in-process.**

Authoritative docs: `gitbooks/developing/architecture.md`, `gitbooks/developing/architecture/frontend.md`, `gitbooks/developing/architecture/tauri-shell.md`.

## Repository

| Path | Role |
|------|------|
| `app/` | pnpm workspace `openhuman-app`: Vite+React (`app/src/`), Tauri host (`app/src-tauri/`), Vitest tests |
| `src/` (root) | Rust crate `openhuman` + `openhuman-core` CLI (`src/main.rs`). `src/openhuman/*` = domains, `src/core/` = transport only (Axum/HTTP, JSON-RPC, CLI, event bus) |
| `Cargo.toml` (root) | Core crate (v0.54.10). `cargo build --bin openhuman-core`. Helpers: `slack-backfill`, `gmail-backfill-3d`, `memory-tree-init-smoke`, `inference-probe` in `src/bin/` |
| `app/src-tauri/Cargo.toml` | Tauri shell, crate `OpenHuman`. Desktop-only. CEF runtime, not WebKit |

## Architecture facts that matter

- **Core is in-process** — no sidecar binary (removed PR #1061). Core runs as a tokio task inside the Tauri host, dies with the GUI. Lifecycle: `core_process::CoreProcessHandle` in `app/src-tauri/src/core_process.rs`.
- **Frontend-to-core RPC** over HTTP at `http://127.0.0.1:<port>/rpc` via `invoke('core_rpc_relay', ...)` — never `fetch()` (CORS preflight). Auth: per-launch hex bearer in `OPENHUMAN_CORE_TOKEN`. Set `OPENHUMAN_CORE_REUSE_EXISTING=1` to attach an externally-started core for debugging.
- **CEF runtime (Chromium)** — not WebKit. Requires the vendored `tauri-cli` from `app/src-tauri/vendor/tauri-cef`. `pnpm dev:app` auto-runs `scripts/ensure-tauri-cli.sh`. Stock `@tauri-apps/cli` produces a broken bundle.
- **Skills runtime removed** — `src/openhuman/skills/` is metadata-only. Do not assume skill packages execute end-to-end.
- **Rust toolchain pinned to 1.93.0** (`rust-toolchain.toml`). Apple Silicon: `GGML_NATIVE=OFF cargo check/build/test`.
- **Dual crate Rust**: root `Cargo.toml` (core lib `openhuman_core`) and `app/src-tauri/Cargo.toml` (shell `OpenHuman`) — independent deps, different test suites. Check both when touching Rust.
- **Business logic in Rust, UI in TS/React**. The Tauri shell is a delivery vehicle (windowing, process lifecycle, IPC). Do not duplicate business rules in `app/`.
- **iOS/Android** use a separate `app/src-tauri-mobile/` with stock `@tauri-apps/cli^2` — NOT the vendored CEF CLI. Not for desktop development.

## Essential commands (run from repo root)

```bash
# Dev servers
pnpm dev                 # Vite-only → port 1420
pnpm dev:app             # Full Tauri desktop with CEF

# Standalone core for debugging
OPENHUMAN_APP_ENV=staging ./target/debug/openhuman-core serve
TOKEN=$(cat ~/.openhuman-staging/core.token)
curl http://localhost:7788/rpc -X POST -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","method":"core.ping","params":{},"id":1}'

# Quality gates
pnpm typecheck           # tsc --noEmit (alias for compile)
pnpm lint                # ESLint
pnpm format              # Prettier + cargo fmt
pnpm format:check        # Prettier + cargo fmt --check

# Tests
pnpm test                # Vitest (app workspace, 1000+ tests)
pnpm test:coverage       # Vitest with coverage
pnpm test:rust           # cargo test via scripts/test-rust-with-mock.sh
pnpm test:rust:e2e       # Rust integration tests (json_rpc_e2e, etc.)
pnpm mock:api            # Start mock API server on :18473

# Rust
cargo check --manifest-path Cargo.toml
cargo build --manifest-path Cargo.toml --bin openhuman-core
cargo test -p openhuman  # Core unit tests (5600+)
cargo check --manifest-path app/src-tauri/Cargo.toml
pnpm rust:check          # same as above

# Focused test runners (see scripts/debug/README.md)
pnpm debug unit src/components/Foo.test.tsx
pnpm debug unit -t "renders empty state"
pnpm debug rust json_rpc_e2e
pnpm debug e2e test/e2e/specs/smoke.spec.ts
```

## Gotchas

- **`pnpm test:unit` does NOT exist at root.** Use `pnpm test` (→ `pnpm --filter openhuman-app test` → `vitest run`). Inside `app/`, `pnpm test:unit` works.
- **`pnpm core:stage` is a no-op** (sidecar removed). Ignore it.
- **`pnpm install` warns** about `@sentry/cli`, `esbuild` build scripts — harmless.
- **Git submodules** required for Tauri shell: `git submodule update --init --recursive`. (CI `build.yml` does this.)
- **Linux Tauri deps**: `libasound2-dev libxi-dev libxtst-dev libxdo-dev libudev-dev libssl-dev clang cmake pkg-config libstdc++-14-dev libgtk-3-dev libwebkit2gtk-4.1-dev libsoup-3.0-dev libjavascriptcoregtk-4.1-dev`
- **Pre-push hook** (`.husky/pre-push`): `format:check` → `lint` → `compile` (tsc) → `rust:check` (Tauri shell) → `lint:commands-tokens`. Auto-fixes prettier/lint. `--no-verify` for pre-existing breakage only; call out in PR body.
- **Coverage gate** ≥80% on changed lines (Vitest + cargo-llvm-cov via `diff-cover`). Run `pnpm test:coverage` + `pnpm test:rust` before PR.
- **No dynamic imports** in production `app/src/` — static `import`/`import type` only. No `React.lazy()`, no `await import()`. Guard heavy paths with `try/catch`.
- **i18n for all UI text**: every user-visible string through `useT()` from `app/src/lib/i18n/I18nContext`. Keys in `app/src/lib/i18n/en.ts`.
- **Auth tokens** live in the in-process core, NOT in redux-persist. Fetched via `fetchCoreAppSnapshot()` RPC.
- **`window.__TAURI__`** is not available at module load. Use `isTauri()` from `app/src/services/webviewAccountService.ts` or wrap `invoke(...)` in `try/catch`.
- **CEF webview injection policy**: Embedded provider webviews (`webview_accounts/`) must have **zero** injected JS. No new `build_init_script`, no CDP `Page.addScriptToEvaluateOnNewDocument`. Use CEF handlers (`on_navigation`, `CefRequestHandler`, etc.) and Rust-side CDP instead. Legacy injection for non-migrated providers (gmail, linkedin, google-meet) is grandfathered but must not grow.
- **Service RPC must use Tauri IPC**: Never `callCoreRpc()` for service operations — it falls back to raw `fetch()` when socket isn't connected, causing CORS errors. Always `invoke('core_rpc_relay', { request: { method, params } })`.
- **`pnpm debug unit` paths are relative to `app/src/`**: Pass `providers/__tests__/Foo.test.tsx`, not the full repo path.
- **Cargo incremental builds can serve stale Tauri UI**: After switching branches, `cargo clean --manifest-path app/src-tauri/Cargo.toml` before rebuild.
- **New Tauri commands need `permissions/` entries**: Each new `#[tauri::command]` must have a matching TOML file in `app/src-tauri/permissions/` or the command silently fails at runtime.

## Provider chain (app/src/App.tsx)

```
Sentry.ErrorBoundary → Redux Provider → PersistGate → BootCheckGate
→ CoreStateProvider → SocketProvider → ChatRuntimeProvider → HashRouter
→ CommandProvider → ServiceBlockingGate → AppShell
```

`CoreStateProvider` owns auth. No `UserProvider`/`AIProvider`/`SkillProvider`.

## Routes (HashRouter, app/src/AppRoutes.tsx)

`/` (Welcome), `/onboarding/*`, `/home`, `/human`, `/intelligence`, `/skills`, `/chat`, `/channels`, `/invites`, `/notifications`, `/rewards`, `/settings/*`. No `/login`, no `/agents`, no `/conversations`.

## Rust module conventions

- **New domains** → dedicated `src/openhuman/<domain>/mod.rs` + siblings. No new files at `src/openhuman/` root.
- **`mod.rs`** → light + export-focused. Code in `ops.rs`, `types.rs`, `store.rs`, `bus.rs`, `schemas.rs`.
- **Domain schemas** → `schemas.rs` in domain dir, exported from `mod.rs`. Wire into `src/core/all.rs`.
- **Controller exposure**: expose to CLI/JSON-RPC through the controller registry only. No domain branches in `src/core/cli.rs` or `src/core/jsonrpc.rs`.
- **Event bus** (`src/core/event_bus/`): singletons. Two surfaces — `publish_global`/`subscribe_global` (broadcast, fire-and-forget) and `register_native_global`/`request_native_global` (typed, zero-serialization, internal-only). Never construct `EventBus`/`NativeRegistry` directly. Each domain owns a `bus.rs`.
- **Rust tests**: prefer `#[cfg(test)] #[path = "..._test.rs"] mod tests;` sibling pattern. No ad-hoc `_test/` dirs for single-module tests.

## Git workflow

- Never write on `main`. Branch from `upstream/main`. Push to `origin` (fork), never `upstream`.
- PRs target `tinyhumansai/openhuman:main`. AI PRs must follow `.github/PULL_REQUEST_TEMPLATE.md` (includes validation checklist).
- Issue/PR templates: `.github/ISSUE_TEMPLATE/{feature,bug}.md`, `.github/PULL_REQUEST_TEMPLATE.md`.

## Debug logging (required)

Verbose diagnostics on new/changed flows. Log entry/exit, branches, external calls, retries, errors. Rust: `tracing` at `debug`/`trace`. `app/`: namespaced `debug`. Grep-friendly prefixes. Never log secrets.

## Feature workflow

1. Rust domain under `src/openhuman/<domain>/` with schemas + registered handlers + unit tests
2. JSON-RPC E2E test (`tests/json_rpc_e2e.rs` via `scripts/test-rust-with-mock.sh`)
3. React UI via `core_rpc_relay`/`coreRpcClient`
4. Vitest + desktop E2E specs
5. Update `src/openhuman/about_app/` if user-facing feature changes

## References

- Env vars: `.env.example` (Rust/Tauri) and `app/.env.example` (VITE_*). Frontend config: `app/src/utils/config.ts` (read VITE_* here, never `import.meta.env` directly).
- E2E guide: `gitbooks/developing/e2e-testing.md`
- Debug runners: `scripts/debug/README.md`
- PR checklist for AI agents: `docs/agent-workflows/codex-pr-checklist.md`
