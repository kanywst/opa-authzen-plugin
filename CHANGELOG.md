# Changelog

All notable changes to opa-authzen-plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions follow the format `<opa_version>-authzen-<N>`, where:
- `<opa_version>` is the OPA version this plugin is built for (e.g., `1.15.1`)
- `<N>` is an incremental counter for plugin releases against that OPA version

## [Unreleased]

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

[Unreleased]: https://github.com/kanywst/opa-authzen-plugin/compare/v0.2.2...HEAD
[v0.2.2]: https://github.com/kanywst/opa-authzen-plugin/compare/v0.2.1...v0.2.2
[v0.2.1]: https://github.com/kanywst/opa-authzen-plugin/compare/v0.2.0...v0.2.1
[v0.2.0]: https://github.com/kanywst/opa-authzen-plugin/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/kanywst/opa-authzen-plugin/compare/v0.0.1...v0.1.0
[v0.0.1]: https://github.com/kanywst/opa-authzen-plugin/releases/tag/v0.0.1
