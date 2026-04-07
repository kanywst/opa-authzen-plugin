# Release Process

This document describes the process for releasing new versions of opa-authzen-plugin.

## Version Scheme

Versions follow the format: **`<opa_version>-authzen-<N>`**

- `<opa_version>`: The OPA version this plugin is built for (e.g., `1.15.1`)
- `<N>`: An incremental counter for plugin releases against that OPA version

**Examples:**
- `1.15.1-authzen-1` — First plugin release for OPA 1.15.1
- `1.15.1-authzen-2` — Second plugin release for OPA 1.15.1
- `1.16.0-authzen-1` — First plugin release for OPA 1.16.0

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
   git tag -a v<opa_version>-authzen-<N> -m "Release v<opa_version>-authzen-<N>"
   git push origin v<opa_version>-authzen-<N>
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
