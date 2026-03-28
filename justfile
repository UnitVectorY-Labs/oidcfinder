
# Commands for oidcfinder
default:
  @just --list
# Build oidcfinder with Go
build:
  go build ./...

# Run tests for oidcfinder with Go
test:
  go clean -testcache
  go test ./...