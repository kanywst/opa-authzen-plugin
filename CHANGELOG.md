# Changelog

All notable changes to opa-authzen-plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

---

## [v0.6.0] - 2026-08-18

First release to reach beyond the AuthZEN 1.0 core into a profile. The 1.0 normative requirements were already fully met and are unchanged.

### Added

- New `supported_obligations` config option: opts the PDP into the [AuthZEN Obligations Profile 1.0](https://openid.github.io/authzen/authzen-obligations-profile-1_0.html). The configured Obligation Types are advertised as the `supported_obligations` member of the PDP metadata document (profile section "Discovery: PDP Metadata Extension"), and the PEP-declared `context.supported_obligations` array is filtered against that set before the input reaches Rego, satisfying the profile's requirement that a PDP ignore any declared value it did not itself advertise ("Negotiation: PEP-Declared Obligation Support"). Filtering applies to both evaluation endpoints and to Search, where it runs before the pagination hash so ignored values cannot invalidate a page token. Unset by default, in which case the metadata member is omitted and request context is passed through untouched, preserving prior behavior. The obligations themselves continue to travel through the existing `decision_context` rule.

### Compatibility

- Built against OPA v1.17.0.
- No behavior change for a deployment that does not set `supported_obligations`: the metadata document is byte-identical and request context still reaches the policy untouched.

---

## [v0.5.1] - 2026-08-03

Packaging only. Plugin behavior is identical to v0.5.0 — `internal/` has no non-comment changes since that release.

### Changed

- Removed `tools.go`. It pinned `github.com/golangci/golangci-lint v1.64.8` in the main `require` block of `go.mod` while doing nothing useful: `go-licenses` was never added to `go.mod`, and `golangci-lint/cmd/golangci-lint` is `package main` and therefore not importable, so building with the `tools` tag failed on both imports. Its only effect was to pull golangci-lint and its transitive dependencies into the module graph of every consumer importing `./plugin`. `go.mod` drops from 261 to 107 lines and `go.sum` from 727 to 275, leaving OPA as the sole direct dependency.
- Lint and license tool versions are now pinned in the `Makefile` and run via `make lint` and `make licenses`. CI derives its golangci-lint version from the same variable, and the linter moves from v2.9.0 to v2.12.2.

### Fixed

- `build/get-opa-version.sh` read the OPA version from a fixed field position, which broke once OPA became the only direct dependency and `go mod tidy` collapsed the require block into a single-line directive. The version is now located by shape and reads correctly in both forms. Release artifacts were unaffected, since the tag workflow passes `VERSION` explicitly.

### Compatibility

- Built against OPA v1.17.0.

---

## [v0.5.0] - 2026-06-28

### Added

- New `decision_context` config option: names a Rego rule whose object value is returned as the Decision's optional `context` member (spec Section 5.5.1), letting a policy convey reasons, obligations, or other metadata alongside the boolean decision. Applies to both `POST /access/v1/evaluation` and the per-evaluation results of `POST /access/v1/evaluations`. The decision and its context are evaluated under a single transaction so they observe the same policy/data snapshot. The rule must evaluate to a JSON object; an undefined result or empty object omits `context`, and a non-object result fails the request. Unset by default, preserving prior behavior.

### Compatibility

- Built against OPA v1.17.0.

---

## [v0.4.0] - 2026-06-06

### Added

- New `capabilities` config block: a list of PDP capability URNs advertised in the `capabilities` field of the PDP metadata document (`GET /.well-known/authzen-configuration`, spec Section 9.1.2). The AuthZEN core registers no capability URNs of its own, so values are operator-supplied; each entry must be a URN (start with `urn:`) and the field is omitted from the metadata when unset.

### Dependencies

- Bump `github.com/open-policy-agent/opa` from 1.16.1 to 1.17.0

---

## [v0.3.0] - 2026-05-13

### Added

- AuthZEN Search APIs (spec Section 8): `POST /access/v1/search/subject`, `POST /access/v1/search/resource`, `POST /access/v1/search/action`
- Stateless opaque-token pagination (Section 8.5) with `next_token`, `count`, and `total` fields; mid-pagination tampering returns 400
- New `search` config block (`subject`, `resource`, `action`, `max_limit`) selecting Rego rules per endpoint
- PDP metadata now advertises `search_subject_endpoint`, `search_resource_endpoint`, and `search_action_endpoint` when the corresponding rule is configured (omitted otherwise per Section 9)
- Example policy rules and config showing how to expose the Search APIs
- `Cache-Control: public, max-age=3600` and `Vary: X-Forwarded-Proto, X-Forwarded-Host` on the PDP metadata response (`GET /.well-known/authzen-configuration`) so PEPs and shared caches can store the discovery document without cross-tenant bleed-over (spec Section 11.9; RFC 9111 §4.1)

### Fixed

- Reject requests where `subject.properties`, `resource.properties`, or `action.properties` is present but not a JSON object (spec Section 5: properties is OPTIONAL and MUST be an object). JSON null is still accepted and silently dropped.
- Search responses now reject policy results that don't conform to the Information Model. Section 8.4 requires `results` to contain only entities of the searched-for type, and Section 5 makes `type`+`id` REQUIRED on Subjects/Resources and `name` REQUIRED on Actions; the plugin verifies each returned entity carries the appropriate strings and returns 500 on a mismatched policy result.

---

## [v0.2.5] - 2026-04-28

### Added

- `input` field included in evaluation Debug log for easier troubleshooting

### Changed

- Increased usage of structured logging (`logger.WithFields`) in evaluation, batch evaluation, and reconfigure paths
- Test helpers accept `testing.TB` so they can be shared between tests and benchmarks
- `mergeField` uses the `isJSONNull` helper instead of raw string comparison for null checks

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

[Unreleased]: https://github.com/kanywst/opa-authzen-plugin/compare/v0.6.0...HEAD
[v0.6.0]: https://github.com/kanywst/opa-authzen-plugin/compare/v0.5.1...v0.6.0
[v0.5.1]: https://github.com/kanywst/opa-authzen-plugin/compare/v0.5.0...v0.5.1
[v0.5.0]: https://github.com/kanywst/opa-authzen-plugin/compare/v0.4.0...v0.5.0
[v0.4.0]: https://github.com/kanywst/opa-authzen-plugin/compare/v0.3.0...v0.4.0
[v0.3.0]: https://github.com/kanywst/opa-authzen-plugin/compare/v0.2.5...v0.3.0
[v0.2.5]: https://github.com/kanywst/opa-authzen-plugin/compare/v0.2.4...v0.2.5
[v0.2.4]: https://github.com/kanywst/opa-authzen-plugin/compare/v0.2.3...v0.2.4
[v0.2.3]: https://github.com/kanywst/opa-authzen-plugin/compare/v0.2.2...v0.2.3
[v0.2.2]: https://github.com/kanywst/opa-authzen-plugin/compare/v0.2.1...v0.2.2
[v0.2.1]: https://github.com/kanywst/opa-authzen-plugin/compare/v0.2.0...v0.2.1
[v0.2.0]: https://github.com/kanywst/opa-authzen-plugin/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/kanywst/opa-authzen-plugin/compare/v0.0.1...v0.1.0
[v0.0.1]: https://github.com/kanywst/opa-authzen-plugin/releases/tag/v0.0.1
