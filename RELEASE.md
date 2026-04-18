# Release Process

This document describes the process for releasing new versions of opa-authzen-plugin.

## Version Scheme

This project currently uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html): **`vMAJOR.MINOR.PATCH`**

> [!NOTE]
> If this project is donated to the `open-policy-agent` org, the version scheme will switch to **`<opa_version>-authzen-<N>`** to match the convention used by [opa-envoy-plugin](https://github.com/open-policy-agent/opa-envoy-plugin) (e.g., `1.15.1-authzen-1`).

## Release Checklist

1. **Verify tests pass**
   ```bash
   make clean build test
   go test -v -race ./...
   ```

2. **Run linting**
   ```bash
   make fmt vet
   golangci-lint run
   ```

3. **Check dependencies**
   ```bash
   go list -m all
   go-licenses check ./...
   ```

4. **Update CHANGELOG.md**
   - Move "Unreleased" section content to new version heading
   - Follow [Keep a Changelog](https://keepachangelog.com/) format
   - Include OPA version compatibility note

5. **Create annotated git tag**
   ```bash
   git tag -a vX.Y.Z -m "Release vX.Y.Z"
   git push origin vX.Y.Z
   ```

6. **Build release artifacts**
   ```bash
   make release
   ```

7. **Create GitHub Release**
   - Push artifacts from `_release/` directory
   - Copy CHANGELOG entry to release notes
   - Mark as "Latest Release" if appropriate

## Pre-Release Checks

### Backward Compatibility
- Run tests on the minimum supported OPA version specified in `go.mod`
- Verify example policies still work
- Check for API-breaking changes

### Dependency Updates
- Run `go get -u` to check for available updates
- Review security advisories: `go list -u -m all`
- Update `go.mod` and `go.sum` if updates are important

### Documentation
- README.md reflects current feature set
- Example policies are up-to-date
- API documentation is accurate

## Troubleshooting

### Docker image build fails
```bash
make docker-build  # Uses git tags for versioning
# Ensure git tags are properly set
git describe --tags --always --dirty
```

### Release artifacts not generated
```bash
make clean release
# Check _release/ directory exists
ls -la _release/
```

## Support & Maintenance

- Monitor for security issues in dependencies via GitHub's Dependabot
- Respond to issues and PRs in a timely manner
- Release patch versions for critical bugs immediately
- Plan minor versions in coordination with OPA releases
