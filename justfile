# Commands for oidcfinder

default:
  @just --list

build:
  mkdir -p bin
  go build -o bin/oidcfinder .

test:
  go test ./...

vet:
  go vet ./...

run *args:
  ./run.sh {{args}}

help:
  go run . help
