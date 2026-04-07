# Changelog

All notable changes to opa-authzen-plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions follow the format `<opa_version>-authzen-<N>`, where:
- `<opa_version>` is the OPA version this plugin is built for (e.g., `1.15.1`)
- `<N>` is an incremental counter for plugin releases against that OPA version

## [Unreleased]

### Added
- Batch evaluations endpoint (`POST /access/v1/evaluations`) with support for:
  - Default subject, action, resource, context fields
  - AuthZEN semantic options: `execute_all`, `deny_on_first_deny`, `permit_on_first_permit`
  - Response format per AuthZEN Section 7
- Well-known configuration endpoint (`GET /.well-known/authzen-configuration`)
- X-Request-ID request/response header support
- Project governance documentation (CONTRIBUTING.md, SECURITY.md, MAINTAINERS.md)
- Go version specification (.go-version)
- Dependabot configuration for automated dependency updates

### Changed
- Simplified go.mod with OPA as an explicit direct dependency

### Fixed

---

## [v0.1.0] - 2026-04-06

### Added
- Initial release
- Single evaluation endpoint (`POST /access/v1/evaluation`) per AuthZEN Section 6
- Rego policy evaluation with configurable package path and decision rule
- Plugin architecture following opa-envoy-plugin standards
- Docker support with example policy
- Comprehensive test suite (49 tests, 81% coverage)

### Features
- AuthZEN Authorization API 1.0 compliance (Sections 5, 6, 7, 9, 10.1.3)
- Direct integration with OPA via ExtraRoute plugin interface
- Full access to OPA's Rego engine, storage, and metrics
- OpenTelemetry tracing support inherited from OPA

---

[Unreleased]: https://github.com/kanywst/opa-authzen-plugin/compare/v0.1.0...HEAD
[v0.1.0]: https://github.com/kanywst/opa-authzen-plugin/releases/tag/v0.1.0
