# Repository Guidelines

## Project Structure & Module Organization

-   `main.go` runs the mock HTTP services and wires the cstore and r1fs handlers.
-   `mock/cstore` and `mock/r1fs` hold the in-memory stores plus unit tests that define expected behaviour. The sandbox mirrors the Ratio1 edge node APIs (https://github.com/Ratio1/edge_node), currently covering [`cstore_manager_api.py`](https://github.com/Ratio1/edge_node/blob/main/extensions/business/cstore/cstore_manager_api.py) and [`r1fs_manager_api.py`](https://github.com/Ratio1/edge_node/blob/main/extensions/business/r1fs/r1fs_manager_api.py).
-   `internal/devseed` exposes helpers for loading JSON seed files used by both mocks.
-   `packaging/macos` contains the launcher script and plist used for signed release bundles.
-   `mock` fixtures and the compiled `r1-plugins-sandbox` binary in the root are safe to regenerate locally.

## Build, Test, and Development Commands

-   `go run .` boots the sandbox with the default ports for iterative development.
-   `go build -o r1-plugins-sandbox` produces the standalone binary that matches release builds.
-   `go test ./...` executes all unit tests in the mock packages; run it before every PR.
-   `./r1-plugins-sandbox --kv-seed seeds/cstore.json --fs-seed seeds/r1fs.json` is a common local launch pattern; adjust paths as needed.

## Coding Style & Naming Conventions

-   Format Go code with `gofmt` (tabs for indentation, blank lines between logical blocks) before committing.
-   Keep exported names CamelCase (`SeedEntries`), and package-private helpers lowerCamelCase.
-   Log messages should stay concise and prefix context, mirroring the existing handlers.
-   Avoid introducing new third-party dependencies without discussing the impact on release artifacts.

## Testing Guidelines

-   Prefer table-driven tests in `mock/*` to cover edge cases around hashing, base64 payloads, and latency/failure toggles.
-   Name tests `Test<Resource><Action>` to align with the current suite (e.g., `TestCStoreSeed`).
-   Use fixtures under `mock` or create temporary files under `t.TempDir()` instead of writing to the repo.
-   Aim to exercise new HTTP handlers through both happy-path and error cases; mimic existing request payload shapes.

## Commit & Pull Request Guidelines

-   Squash work-in-progress commits before review; keep the diff focused on one change set.
-   PRs should describe the motivation, summarize behavioural changes, list test commands, and link to tracking issues.
-   Include screenshots or sample responses when altering HTTP output so reviewers can validate clients quickly.
