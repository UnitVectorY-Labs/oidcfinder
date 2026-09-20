# oidcfinder

A deterministic, rate-limited crawler that finds public OpenID Connect and OAuth authorization-server metadata for the [JWKS Catalog](https://github.com/UnitVectorY-Labs/jwks-catalog). Give it a Cloudflare domain list; review validated discoveries in a terminal UI and export accepted entries as catalog-compatible YAML.

No LLM, Cloudflare API key, or OpenCode installation is needed.

## Quick start

Requires Go 1.26+ and a C compiler for SQLite (`CGO_ENABLED=1`).

```sh
go build -o bin/oidcfinder .

# Use your downloaded Cloudflare CSV; runtime inputs and outputs stay ignored.
./bin/oidcfinder crawl \
  --domains data/cloudflare-radar_top-100-domains_20260920.csv \
  --prefixes prefixes.yaml

./bin/oidcfinder tui
./bin/oidcfinder status
```

`./run.sh <command> [flags]` builds and runs the same binary. The default database is `data/crawler.db`; accepted services go to `data/accepted.yaml`. Use `--db PATH` on every command to select another database. Export defaults to `accepted.yaml` alongside that database; `tui` and `export` also accept `--export PATH`.

## Crawl

Every invocation downloads the latest [services.yaml](https://raw.githubusercontent.com/UnitVectorY-Labs/jwks-catalog/refs/heads/main/data/services.yaml), reconciles candidate membership, imports domains, and drains the due queue. A failed catalog refresh stops the crawl. There is no silent fallback to stale catalog data.

Input can be Cloudflare `rank,domain,categories` CSV, a CSV with a named `domain` column, headerless `rank,domain` CSV, or one domain per line. Domain names are normalized, including internationalized names; malformed rows stop ingestion with a row number. Large files stream through transactions of 1,000 domains. Previously committed batches remain resumable if input parsing fails later.

The apex and each configured prefix are probed over HTTPS at:

- `/.well-known/openid-configuration`
- `/.well-known/oauth-authorization-server`

Edit `prefixes.yaml` to change the search space. Multi-label prefixes such as `token.actions` work; `prefixes: []` scans only apex domains. Omitting `--prefixes` uses the same built-in common prefixes. Importing again adds missing targets without resetting their dates. Removing a prefix does not delete already queued targets. The queue belongs to the database, so a crawl also processes due targets imported by earlier invocations.

| Flag | Default | Purpose |
| --- | --- | --- |
| `--workers` | `4` | Concurrent target workers, maximum 32 |
| `--interval` | `500ms` | Global gap between requests, minimum 50ms |
| `--site-interval` | `2s` | Gap per registrable domain, minimum 500ms |
| `--timeout` | `15s` | Request deadline after waiting for pacing |
| `--positive-ttl` | `168h` | Revisit valid or catalog targets after seven days |
| `--negative-ttl` | `720h` | Revisit negative results after 30 days |
| `--retry-ttl` | `24h` | Retry network errors, HTTP 429, and server errors |
| `--limit` | `0` | Maximum targets this invocation; zero drains all due targets |
| `--catalog-file` | unset | Local catalog override for controlled tests |
| `--catalog-url` | official URL | Alternate remote catalog source |

Pacing includes discovery, JWKS, and redirect requests. Subdomains share a site budget using the Public Suffix List. HTTP 429/503 `Retry-After` is honored up to 24 hours and extends retry dates for all queued targets at that site, including across restarts. Use one crawler/database for a workload: separate databases have separate rate budgets. A renewable database lease prevents concurrent crawls against the same database.

Ctrl-C cancels network work. Completed targets are saved; rerun the command to resume. Each invocation visits only targets due when scanning begins, so it finishes even with short retry intervals. Run the same command periodically through cron or another scheduler for ongoing discovery.

### What counts as a candidate?

A 200 response alone is insufficient. The crawler requires JSON metadata with an HTTPS issuer and JWKS URL, validates the expected OIDC fields (or OAuth authorization/token metadata), fetches the JWKS, and checks for nonempty public RSA, EC, or signing OKP key material. Empty sets, private keys, arbitrary JSON, HTML, oversized responses, and failed key fetches do not become candidates. This is discovery and structural validation, not a certification of protocol compliance or service ownership.

HTTPS certificate verification remains enabled. Private/local destinations, non-HTTPS redirects, and credentials in URLs are blocked. Requests and redirects have bounded time, size, and count. No credentials are sent, and environment HTTP proxies are not used.

Discovery is deliberately bounded to the configured hostnames and two root paths. It does not enumerate tenants, scrape links, guess realm names, or find arbitrary path-based issuers such as `/common/v2.0` or `/realms/example`.

## Review and export

In `tui`:

| Key | Action |
| --- | --- |
| ↑ / ↓ or j / k | Select candidate |
| Enter | Inspect endpoints, dates, and metadata; arrows scroll |
| a | Accept; edit service ID/name, Tab switches fields, Enter saves |
| r | Reject |
| u | Undo rejection and return to pending |
| Tab | Cycle pending, accepted, rejected, catalog, and all views |
| / | Search issuer or name |
| n / p | Next/previous page (50 candidates per page) |
| F5 | Refresh while a separate crawl is running |
| Esc | Close details or cancel a form |
| q / Ctrl-C | Quit |

Acceptance appends or updates an entry in the selected YAML file using an atomic replacement, then records the decision. Existing entries are preserved, repeated acceptance does not duplicate entries, and conflicting service IDs fail without changing the decision. Keep one export file per database; do not manually edit it while reviewing. Export files use the JWKS Catalog's `services:` structure:

```yaml
services:
  - id: example
    name: Example
    openid-configuration: https://accounts.example.com/.well-known/openid-configuration
    oauth-authorization-server: https://accounts.example.com/.well-known/oauth-authorization-server
    jwks_uri: https://accounts.example.com/keys
```

Review the generated ID and name before acceptance. Copy approved entries into `jwks-catalog/data/services.yaml` through its normal contribution process. This application does not publish or modify the official catalog.

**Accepted and in-catalog are independent.** Acceptance never claims an entry is in the catalog. Only the next catalog refresh can establish membership, matching exact discovery or JWKS URLs. Known discovery URLs are skipped; a newly discovered URL pointing to a catalog JWKS is retained with its catalog flag. Rejected and accepted decisions survive recrawls. Accepted entries cannot be rejected with a single key because they have already been exported; edit the contribution explicitly if it needs correction.

```sh
# Restore accepted entries into a missing file, or export to another file.
./bin/oidcfinder export --export data/accepted-copy.yaml
```

SQLite and YAML cannot share a transaction. If the process stops after replacing YAML but before committing acceptance, repeat acceptance: it is idempotent. A failed YAML write leaves the decision unchanged. `export` can regenerate accepted entries from the database.

## Storage and maintenance

`data/` is ignored, including downloaded rankings, SQLite files, exports, and test artifacts. SQLite uses WAL, a busy timeout, unique target/candidate indexes, and an indexed due queue. It retains one compact result per target and the latest metadata per issuer/JWKS pair, not response bodies or an ever-growing attempt log. First-seen, last-attempt, next-attempt, attempt count, first-discovered, and last-validated dates are retained. Queue and review pages are bounded in memory. Back up SQLite with its backup API or stop the processes before copying the database and its WAL files.

The retired agent database (`data/oidcfinder.db`) is not migrated or modified. The new default is `data/crawler.db`; explicitly opening the old schema produces an actionable error. The LLM orchestration, packet importer, and old CLI commands have been removed.

## Development and verification

`main.go` is only the process entry point; application code lives in `internal/oidcfinder/`.

```sh
go test ./...
go test -race ./...
go vet ./...
```

Tests cover metadata/JWKS validation, pacing and cancellation, CSV ingestion, 100,000-domain import, lease exclusion, retry scheduling, catalog reconciliation, durable decisions, export failure/collision handling, and TUI interactions. `go test -short ./...` skips the scale test.

To check live rediscovery, use a **local copy** of the catalog with Google's entry removed, a separate database, and a domain list containing `google.com` with the `accounts` prefix:

```sh
./bin/oidcfinder crawl --domains data/google-test.txt \
  --prefixes data/google-prefixes.yaml \
  --catalog-file data/catalog-without-google.yaml --db data/rediscovery.db
./bin/oidcfinder tui --db data/rediscovery.db
```

Google should appear for review. Rerun immediately to verify zero targets are rescanned; then rerun without `--catalog-file` to verify the official catalog flags the discovery. This leaves the official catalog unchanged. See [verification notes](docs/verification.md) for the completed test runs.
