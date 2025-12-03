[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT) [![Work In Progress](https://img.shields.io/badge/Status-Work%20In%20Progress-yellow)](https://guide.unitvectorylabs.com/bestpractices/status/#work-in-progress) [![Go Report Card](https://goreportcard.com/badge/github.com/UnitVectorY-Labs/oidcfinder)](https://goreportcard.com/report/github.com/UnitVectorY-Labs/oidcfinder)

# oidcfinder

Automates the discovery of OpenID Connect configuration URLs across list of domains.

## What This Application Does

**oidcfinder** streamlines the process of OIDC endpoint discovery by:

- **Batch Testing**: Process multiple domains from a file simultaneously with configurable parallel workers
- **OIDC Detection**: Automatically tests domains for the presence of `/.well-known/openid-configuration` endpoints
- **Persistent Storage**: Maintains a SQLite database to track tested domains and their OIDC status, avoiding calls to already tested domains
- **Domain Management**: Provides commands to manually add, remove, and list valid/invalid domains
- **Flexible Output**: Optionally saves discovered OIDC endpoint URLs to an output file
- **Timeout Handling**: Configurable request timeouts to handle slow or unresponsive domains
- **Domain Prefixing**: Supports adding prefixes to domains for searching common OIDC subdomains (e.g., `auth.example.com`)

The tool checks if domains respond with a valid JSON response at the OIDC well-known configuration endpoint and categorizes them as valid (has OIDC) or invalid (no OIDC) domains.

## Installation

```bash
go install github.com/UnitVectorY-Labs/oidcfinder@latest
```

## Usage

oidcfinder requires exactly one action to be specified. The available actions are:

### Test Domains from File

```bash
oidcfinder -file domains.txt [OPTIONS]
```

Process a list of domains from a file (one domain per line) and test each for OIDC endpoints. This is the primary action for batch testing. It is recommended to use the `-parallel` option to speed up the testing process by running multiple requests concurrently on longer lists of domains.  It is also recommended to specify the `-out` option to save discovered OIDC endpoint URLs to a file to easily reference after the command completes.

### List Known Domains

```bash
oidcfinder -list
```

Display all domains currently stored in the database, separated into valid (has OIDC) and invalid (no OIDC) categories.

### Manual Domain Management

```bash
# Add domains manually
oidcfinder -add-valid example.com
oidcfinder -add-invalid badexample.com

# Remove domains
oidcfinder -remove-valid example.com
oidcfinder -remove-invalid badexample.com
oidcfinder -remove example.com  # Remove from any list
```

## Command Line Arguments

### Actions

Only one action is required at a time. The available actions are:

| Flag                       | Description                                                    |
|----------------------------|----------------------------------------------------------------|
| `-file <path>`             | Path to file containing domains to execute test (one per line) |
| `-list`                    | List all valid and invalid domains in the database             |
| `-add-valid <domain>`      | Manually add a domain to the valid (has OIDC) list             |
| `-add-invalid <domain>`    | Manually add a domain to the invalid (no OIDC) list            |
| `-remove-valid <domain>`   | Remove a domain from the valid list                            |
| `-remove-invalid <domain>` | Remove a domain from the invalid list                          |
| `-remove <domain>`         | Remove a domain from any list (valid or invalid)               |

### Options

The following options are optional:

| Flag                | Type    | Default      | Description                                                                        |
|---------------------|---------|--------------|------------------------------------------------------------------------------------|
| `-db <path>`        | string  | `domains.db` | SQLite database file path for storing results                                      |
| `-prefix <prefix>`  | string  |              | Prefix to add to domains from file (e.g., `-prefix auth` tests `auth.example.com`) |
| `-out <path>`       | string  |              | Output file to append discovered OIDC endpoint URLs                                |
| `-parallel <num>`   | int     | `1`          | Number of parallel workers for concurrent domain testing                           |
| `-timeout <seconds>`| int     | `30`         | HTTP request timeout in seconds                                                    |


## Output Format

When testing domains, oidcfinder provides real-time feedback:

- `✅` - OIDC endpoint found
- `❌` - No OIDC endpoint 
- `⏰` - Request timed out (domain not added to database)
- `already known` - Domain previously tested (skipped)

## Database Schema

The tool creates a SQLite database with the following schema:

```sql
CREATE TABLE domains (
    name TEXT PRIMARY KEY,
    has_oidc BOOLEAN NOT NULL,
    tested_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

This database tracks each domain's name, whether it has an OIDC endpoint, and the last time it was tested so that redundant tests can be avoided as a single HTTP GET request will be made for each domain only once.
