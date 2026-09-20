# oidcfinder agent instructions

This repository is a deterministic Go crawler and review TUI for discovering
public OIDC and OAuth authorization-server endpoints for the JWKS Catalog.
There is no LLM discovery or OpenCode runtime.

Keep main.go as the process entry point and application code under internal/.
Use ./run.sh <command> or build with `go build -o bin/oidcfinder .`.
The primary commands are crawl, tui, status, and export.

Only validated metadata plus public JWKS key material can create candidates.
Review decisions and official catalog membership are independent. A recrawl
must preserve accepted and rejected decisions. Refresh the official catalog
before crawling; never silently fall back to stale catalog data.

Keep requests bounded and paced globally and per registrable domain. Preserve
retry dates and avoid unbounded response logs, queues, or in-memory imports.
Do not disable TLS verification or permit private network targets.

Runtime data, downloaded domain lists, credentials, SQLite, exports, logs,
and binaries belong under ignored data/ or bin/. Never commit data/ or .env.
Do not modify sibling oidc-hunter or jwks-catalog repositories for this task.

When changing CLI behavior, update README.md and tests. Run go test ./...,
go test -race ./..., and go vet ./... for substantive engine changes.
Use isolated databases and local catalog copies for rediscovery tests.
