# Verification

Local verification on September 20, 2026, using Go 1.27.1 on macOS/arm64. Network results describe this run, not a guarantee that a service will remain available.

## Automated checks

`go test ./...`, `go test -race ./...`, `go vet ./...`, and the native build passed. The real TUI acceptance flow and CLI re-export were also exercised; the exported YAML files matched exactly.

The test suite exercises streamed CSV import, IDNA normalization, duplicate suppression, metadata and key validation, body/redirect limits, blocked network destinations, global and per-site pacing, timeout/cancellation behavior, persistent server cooldowns, retry dates, crawl leases, catalog refresh atomicity, durable review decisions, YAML collision handling, and TUI review interactions.

The scale test imported **100,000 domains and 300,000 targets in 1.56 seconds**, using **40.5 MiB** of SQLite pages on this machine. `EXPLAIN QUERY PLAN` confirmed the due queue uses `targets_due`. This measures ingestion and storage; it does not imply a comparable network crawl rate. Network requests remain deliberately paced.

## Controlled live rediscovery

A local copy of the 364-service official catalog excluded only the `google` entry. An isolated crawl of `google.com` plus the `accounts` prefix:

1. Validated Google's OIDC and OAuth metadata and fetched its JWKS.
2. Merged both documents into one pending candidate.
3. Scanned **zero targets** on an immediate repeat.
4. Exported one entry through a real interactive TUI session and recorded it as accepted.
5. Refreshed the official catalog, setting membership to true while preserving acceptance.

The official catalog and sibling repositories were not changed. All inputs, databases, YAML exports, and logs for these checks remain under ignored `data/`.

## Cloudflare top 100

The downloaded `cloudflare-radar_top-100-domains_20260920.csv` contains 100 domains. The default 11 prefixes plus apex produce **1,200 unique targets**. The crawl used a global 500 ms request gap and a two-second site gap. It was deliberately interrupted and resumed during verification to check that completed targets retain their retry dates. The final resumed pass used 16 workers and a six-second network timeout; the production defaults remain four workers and 15 seconds.

All **1,200 targets were processed exactly once** across the resumed passes. An immediate repeat refreshed the catalog, added no targets, and reported **scanned=0**.

| Latest target result | Count |
| --- | ---: |
| Negative | 1,106 |
| Transient failure, scheduled for retry | 76 |
| Valid metadata and JWKS | 10 |
| Known catalog discovery URL | 8 |

The ten valid targets merged into seven candidate identities: three matched the catalog and four remain pending review:

- `https://auth.openai.com`
- `https://login.appsflyer.com/`
- `https://signin.playstation.net`
- `https://www.whatsapp.com`

These are review candidates, not automatic catalog additions. Transient results are not evidence that a domain lacks an endpoint. The six-second test timeout is shorter than the default, and those targets remain eligible for a later retry.

The completed database passed SQLite's integrity check and was copied through SQLite's backup API to the default `data/crawler.db`. Run `./run.sh tui` to inspect the four pending candidates. The controlled Google acceptance remains confined to its separate test database and YAML file.
