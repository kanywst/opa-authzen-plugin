# Changelog

All notable changes to opa-authzen-plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

---

## [v0.2.4] - 2026-04-18

### Added
- Envoy Gateway integration example (`example/envoy-gateway/`)
  - ext-authz-bridge: translates Envoy gRPC ext_authz into AuthZEN evaluation requests
  - Docker Compose setup with Envoy, bridge, OPA, and backend services
  - Smoke test script (`test.sh`) covering 9 authorization scenarios
- Strict information model validation with field-level error messages (e.g., "`subject.type` is required and must be a string")
- Regression tests for malformed requests (23 cases covering type mismatches, null, arrays)
- Tests for JSON null `context` treated as absent (single and batch endpoints)

### Changed
- Renamed `supported_capabilities` to `capabilities` in PDP metadata (aligns with Editor's Draft / IANA registry)
- Version scheme documentation updated to reflect current semver usage

### Fixed
- JSON null `context` no longer rejected as invalid (`context` is OPTIONAL per Section 6)
- Required field null handling consistent between single and batch endpoints

---

## [v0.2.3] - 2026-04-16

### Added
- Todo app example with RBAC + resource ownership based on AuthZEN Interop scenario
- ABAC example with clearance levels, department matching, and context-based approval
- X-Request-ID echo on well-known metadata endpoint (Section 10.1.3)
- Tests for well-known X-Request-ID echo and empty `supported_capabilities` omission

### Fixed
- Empty `supported_capabilities` now omitted from well-known response per Section 9.2.2 MUST
- Removed unnecessary explicit initialization of `SupportedCapabilities` field

### Dependencies
- Bump `github.com/open-policy-agent/opa` from 1.15.1 to 1.15.2
- Bump `actions/checkout` from 4 to 6
- Bump `actions/github-script` from 8 to 9
- Bump `docker/setup-buildx-action` from 3 to 4
- Bump `golangci/golangci-lint-action` from 7 to 9

---

## [v0.2.2] - 2026-04-11

### Added
- `supported_capabilities` field in well-known metadata response (Section 9, 12.3)
- AuthZEN interop E2E test suite integration

### Changed
- Well-known metadata response uses typed struct instead of untyped map

### Fixed
- Explicit JSON `null` in batch evaluation fields now correctly falls back to top-level defaults (Section 7.1.1)

---

## [v0.2.1] - 2026-04-11

### Added
- Request payload size limit (1 MB) and batch size limit (100 evaluations) (Section 11.7)
- Race detector and golangci-lint in CI

### Changed
- Batch size limit exceeded now returns 413 Request Entity Too Large
- Improved error handling with HTTP status codes in per-evaluation error responses
- golangci-lint v2 migration with updated configuration

### Fixed
- errcheck lint errors in test code

---

## [v0.2.0] - 2026-04-07

### Added
- Batch evaluations endpoint (`POST /access/v1/evaluations`) with support for:
  - Default subject, action, resource, context fields (Section 7.1.1)
  - AuthZEN semantic options: `execute_all`, `deny_on_first_deny`, `permit_on_first_permit` (Section 7.1.2.1)
  - Per-evaluation error responses (Section 7.2.1)
  - Backward compatibility when `evaluations` array is absent or empty (Section 7.1)
- Well-known configuration endpoint (`GET /.well-known/authzen-configuration`)
- X-Request-ID request/response header support (Section 10.1.3)
- Content-Type validation for API requests (Section 10.1)
- Project governance documentation (CONTRIBUTING.md, SECURITY.md, MAINTAINERS.md, CODE_OF_CONDUCT.md)
- RELEASE.md with versioning scheme and release checklist
- Go version specification (.go-version)
- Dependabot configuration for automated dependency updates
- tools.go for golangci-lint and go-licenses

### Changed
- Simplified go.mod with OPA as an explicit direct dependency
- Release script auto-generates release notes

---

## [v0.1.0] - 2026-04-05

### Added
- Single evaluation endpoint (`POST /access/v1/evaluation`) per AuthZEN Section 6
- Required field validation for subject, action, resource
- Content-Type validation
- Release workflow and CODEOWNERS
- Rego policy evaluation with configurable package path and decision rule
- Plugin architecture following opa-envoy-plugin standards
- Docker support with example policy

---

## [v0.0.1] - 2026-04-02

### Added
- Initial release
- AuthZEN authorization plugin for OPA
- Main entry point for OPA authzen plugin

---

[Unreleased]: https://github.com/kanywst/opa-authzen-plugin/compare/v0.2.4...HEAD
[v0.2.4]: https://github.com/kanywst/opa-authzen-plugin/compare/v0.2.3...v0.2.4
[v0.2.3]: https://github.com/kanywst/opa-authzen-plugin/compare/v0.2.2...v0.2.3
[v0.2.2]: https://github.com/kanywst/opa-authzen-plugin/compare/v0.2.1...v0.2.2
[v0.2.1]: https://github.com/kanywst/opa-authzen-plugin/compare/v0.2.0...v0.2.1
[v0.2.0]: https://github.com/kanywst/opa-authzen-plugin/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/kanywst/opa-authzen-plugin/compare/v0.0.1...v0.1.0
[v0.0.1]: https://github.com/kanywst/opa-authzen-plugin/releases/tag/v0.0.1
