# sbox

This directory contains the Go module for sbox. See the
[project README](../README.md) for usage, the security model, and known limits.

```sh
CGO_ENABLED=0 go build -o sbox ./cmd/sbox
go vet ./...
go test ./...
go test -race ./...
```

The binary requires Linux, bwrap, and socat (`--net` needs only bwrap).
Builds require Go 1.22 or newer. The race detector additionally needs a C
compiler. Tests use native Go assertions and checked-in fixtures.
