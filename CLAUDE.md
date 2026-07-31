# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

An OPA plugin (OPA-AuthZEN) that implements the [OpenID AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html) as a native OPA plugin. It registers AuthZEN endpoints (`/access/v1/evaluation`, `/access/v1/evaluations`, `/.well-known/authzen-configuration`) on OPA's own HTTP server using OPA's `ExtraRoute` extension point.

## Prerequisites

Go 1.26.1+. Tool dependencies (golangci-lint, go-licenses) are managed via `tools.go` build tag.

## Commands

```bash
make build          # Build binary → ./opa-authzen-plugin
make test           # Run all tests (go test -v ./...)
make fmt            # Format code
make vet            # Vet code
make clean          # Remove build artifacts
make release        # Cross-compile for linux/darwin/windows (amd64+arm64)
make docker-build   # Build Docker image
make docker-run     # Run in Docker with example config
make test-interop   # E2E tests via opa-authzen-interop (clones external repo)
```

Run a single test:

```bash
go test -v -run TestEvaluationAllow ./internal/
```

Run tests with race detector:

```bash
go test -v -race ./...
```

Run benchmarks:

```bash
go test -bench=. ./internal/
```

Lint (golangci-lint v2, config in `.golangci.yaml`):

```bash
golangci-lint run
```

## Architecture

Three-layer structure with a thin public API:

- **`cmd/opa-authzen-plugin/main.go`** — Entry point. Registers the plugin factory with OPA's runtime, then delegates to OPA's root command. This binary *is* OPA with the AuthZEN plugin compiled in.
- **`plugin/plugin.go`** — Public plugin interface. Exports `PluginName` and `Factory` (implements `plugins.Factory`). Thin wrapper that delegates to `internal`.
- **`internal/internal.go`** — All plugin logic: config parsing, HTTP handlers for evaluation/evaluations/well-known endpoints, OPA policy evaluation via `rego.New()`, batch semantics (execute_all, deny_on_first_deny, permit_on_first_permit), request validation, and field merging for batch defaults (Section 7.1.1).

The `plugin` package exists so users can import the factory without depending on internal implementation details.

## Configuration

Plugin is configured under `plugins.authzen` in OPA's config YAML:

- `path` (default: `"authzen"`) — OPA package path to query
- `decision` (default: `"allow"`) — Rule name that produces the boolean decision

Policy must be in `package <path>` and define a rule named `<decision>`.

## Key Conventions

- All tests use `httptest.NewRecorder` and a helper `testPlugin()` function defined in the test file — no external test infrastructure needed.
- The AuthZEN spec section numbers are referenced in comments throughout (e.g., "Section 7.1.1", "Section 11.7") — preserve these references when modifying code.
- `json.RawMessage` is used for request fields to defer unmarshalling and support the default-merging pattern in batch evaluations.
- All commits must include DCO sign-off (`git commit -s`).

## Versioning

Release versions combine the OPA upstream version with a plugin-specific revision, computed by `build/get-opa-version.sh` and `build/get-plugin-rev.sh`. See `RELEASE.md` for the scheme.

## Internal Directories

- `_contexts/authzen/` — AuthZEN spec source (Editor's Draft). Reference when checking spec compliance.
- `_roadmap/` — Donation roadmap to `open-policy-agent` org (gitignored, local only).
- `_review/` — Design docs and spec review notes for PR context.
- `example/` — Working examples including OPA config, policy files, and an Envoy Gateway integration with ext-authz bridge.
